

(() => {

// DefenceLogic Client Exposure Inspector
// Read-only client-side analysis
// Version: 1.0

if (window.__DEFENCELOGIC_INSPECTOR_LOADED__) {
  console.warn("DefenceLogic Inspector already loaded");
  return;
}
window.__DEFENCELOGIC_INSPECTOR_LOADED__ = true;
  /**********************************************************
   * SAFE RENDERING (CSP / Trusted Types safe)
   **********************************************************/
  const safeRenderHTML = (html) => {
    try {
      const win = window.open("about:blank", "_blank");
      if (win && win.document) {
        win.document.open();
        win.document.write(html);
        win.document.close();
        return;
      }
    } catch {}

    try {
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      window.open(url, "_blank");
      return;
    } catch {}

    console.warn("[!] Rendering blocked — JSON export still available");
  };

  /**********************************************************
   * HELPERS
   **********************************************************/
  const uniq = (arr) => [...new Set(arr)].filter(Boolean);

  const safeTypeof = (obj, key) => {
    try { return typeof obj[key]; } catch { return "unreadable"; }
  };

  const re = (s) => new RegExp(s, "g");

  /**********************************************************
   * 1) INVENTORY: GLOBAL VARS (non-functions)
   **********************************************************/
  const globalVars = Object.keys(window)
    .filter(k => {
      try {
        return typeof window[k] !== "function" && k !== "window" && k !== "document";
      } catch { return false; }
    })
    .map(name => ({ name, type: safeTypeof(window, name) }));

  const globalVarNames = globalVars.map(v => v.name);

  /**********************************************************
   * 2) INVENTORY: ACCESSIBLE COOKIES (non-HttpOnly)
   **********************************************************/
  const cookies = document.cookie
    ? document.cookie.split(";").map(c => {
        const [name, ...rest] = c.trim().split("=");
        return { name, value: rest.join("=") };
      })
    : [];

  /**********************************************************
   * 3) INVENTORY: GLOBAL FUNCTIONS (non-native)
   **********************************************************/
  const functions = Object.keys(window)
    .filter(k => typeof window[k] === "function")
    .map(name => {
      let source;
      try { source = window[name].toString(); }
      catch { source = "[unreadable]"; }
      return { name, source };
    })
    .filter(f => !f.source.includes("[native code]"));

  /**********************************************************
   * 4) HEURISTICS: SOURCES / SINKS / ENDPOINTS
   **********************************************************/
  // "Sources" are places user-controlled data commonly comes from (not exhaustive).
  const SOURCE_PATTERNS = [
    { label: "location.search", regex: /\blocation\.search\b/ },
    { label: "location.hash", regex: /\blocation\.hash\b/ },
    { label: "document.cookie", regex: /\bdocument\.cookie\b/ },
    { label: "document.referrer", regex: /\bdocument\.referrer\b/ },
    { label: "localStorage", regex: /\blocalStorage\b/ },
    { label: "sessionStorage", regex: /\bsessionStorage\b/ },
    { label: "DOM input (.value)", regex: /\.value\b/ },
    { label: "URLSearchParams", regex: /\bURLSearchParams\b/ },
  ];

  // "Sinks" are dangerous output/execution points (DOM XSS / script injection / navigation).
  const SINK_PATTERNS = [
    { label: "innerHTML assignment", regex: /\.innerHTML\s*=/ },
    { label: "outerHTML assignment", regex: /\.outerHTML\s*=/ },
    { label: "insertAdjacentHTML", regex: /\.insertAdjacentHTML\s*\(/ },
    { label: "document.write()", regex: /\bdocument\.write\s*\(/ },
    { label: "eval()", regex: /\beval\s*\(/ },
    { label: "Function()", regex: /\bnew\s+Function\b|\bFunction\s*\(/ },
    { label: "setTimeout(string)", regex: /\bsetTimeout\s*\(\s*['"`]/ },
    { label: "setInterval(string)", regex: /\bsetInterval\s*\(\s*['"`]/ },
    { label: "location assignment", regex: /\b(?:window\.)?location\s*=/ },
    { label: "window.open()", regex: /\bwindow\.open\s*\(/ },
  ];

  // Endpoints / URLs: conservative extraction — captures common hardcoded paths and API usage.
  const ENDPOINT_REGEXES = [
    /fetch\s*\(\s*(['"`])(.*?)\1/gi,
    /open\s*\(\s*(['"`])(.*?)\1/gi, // xhr.open("GET", "/path")
    /url\s*:\s*(['"`])(.*?)\1/gi,   // $.ajax({url:"/path"})
    /(['"`])(\/api\/[a-zA-Z0-9/_-]+)\1/gi,
    /(['"`])(\/[a-zA-Z0-9/_-]+\.php(?:\?[a-zA-Z0-9=&_%\-]*)?)\1/gi,
    /(['"`])(\/[a-zA-Z0-9/_-]+\.json(?:\?[a-zA-Z0-9=&_%\-]*)?)\1/gi,
  ];

  // Storage read/write patterns (helps correlation + benign/risky classification).
  const STORAGE_READ_PATTERNS = [
    { label: "localStorage.getItem", regex: /\blocalStorage\.getItem\s*\(/ },
    { label: "sessionStorage.getItem", regex: /\bsessionStorage\.getItem\s*\(/ },
    { label: "document.cookie (read)", regex: /\bdocument\.cookie\b/ },
  ];

  const STORAGE_WRITE_PATTERNS = [
    { label: "localStorage.setItem", regex: /\blocalStorage\.setItem\s*\(/ },
    { label: "sessionStorage.setItem", regex: /\bsessionStorage\.setItem\s*\(/ },
    // writing document.cookie is nuanced, still useful:
    { label: "document.cookie (write)", regex: /\bdocument\.cookie\s*=/ },
  ];

  /**********************************************************
   * 5) EXTRA PENTEST FLAGS (high value / low noise)
   **********************************************************/
  // Reverse tabnabbing: window.open without noopener/noreferrer in feature string.
  // Heuristic: detect window.open(...) and absence of "noopener"/"noreferrer" literals anywhere in function.
  const hasTabnabbingRisk = (src) => {
    const hasOpen = /\bwindow\.open\s*\(/.test(src);
    if (!hasOpen) return false;
    const hasNoop = /\bnoopener\b/i.test(src);
    const hasNoref = /\bnoreferrer\b/i.test(src);
    return !(hasNoop || hasNoref);
  };

  // postMessage listener without obvious origin check:
  // heuristic: addEventListener('message'...) exists AND no "origin" substring appears.
  const hasWeakPostMessageHandling = (src) => {
    const hasListener =
      /\baddEventListener\s*\(\s*['"]message['"]/.test(src) ||
      /\bonmessage\b/.test(src);
    if (!hasListener) return false;
    const mentionsOrigin = /\borigin\b/.test(src);
    return !mentionsOrigin;
  };

  /**********************************************************
   * 6) ANALYZE EACH FUNCTION
   **********************************************************/
  const analyzedFunctions = functions.map(fn => {
    const src = fn.source;

    // Globals referenced
    const globalsUsed = globalVarNames.filter(v => new RegExp(`\\b${v}\\b`).test(src));

    // Sources/sinks usage
    const sourcesUsed = SOURCE_PATTERNS.filter(p => p.regex.test(src)).map(p => p.label);
    const sinksUsed = SINK_PATTERNS.filter(p => p.regex.test(src)).map(p => p.label);

    // Storage usage
    const storageReads = STORAGE_READ_PATTERNS.filter(p => p.regex.test(src)).map(p => p.label);
    const storageWrites = STORAGE_WRITE_PATTERNS.filter(p => p.regex.test(src)).map(p => p.label);
    const usesStorage = storageReads.length > 0 || storageWrites.length > 0;

    // Endpoints extraction
    const endpoints = [];
    for (const rgx of ENDPOINT_REGEXES) {
      let m;
      while ((m = rgx.exec(src)) !== null) {
        const url = m[2];
        // filter obvious junk
        if (url && url.length >= 2 && !url.startsWith("javascript:")) endpoints.push(url);
      }
    }
    const endpointsUniq = uniq(endpoints);

    // Key “danger” indicators
    const hasEval = /\beval\s*\(|\bnew\s+Function\b|\bFunction\s*\(/.test(src);
    const hasDynamicInput = /(\+|\$\{|\barguments\b|\bvalue\b|\bevent\b|\bdecodeURI\b|\bdecodeURIComponent\b)/.test(src);

    // ✅ Auto-flag eval + user/dynamic input combos
    const evalWithInput = hasEval && hasDynamicInput;

    // ✅ Storage → Sink correlation
    // Heuristic: storage read + any DOM/execution sink in same function
    const storageToSink = (storageReads.length > 0) && (
      /\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(|\beval\s*\(|new\s+Function|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`]/.test(src)
    );

    // ✅ Storage-backed XSS patterns (stronger hint)
    // Look for "getItem" value used in HTML sinks or eval-ish sinks
    const storageBackedXSSHint =
      /getItem\s*\([\s\S]{0,120}\)\s*\)|document\.cookie/.test(src) &&
      (/\.innerHTML\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(|\beval\s*\(|new\s+Function/.test(src));

    // ✅ Benign vs risky storage usage
    // - benign: only storage reads/writes + no sinks + no endpoints + no eval flags
    // - risky: storage -> sink OR storageBackedXSSHint OR evalWithInput
    // - potentially risky: uses storage + (endpoints or sources) but no sinks
    let storageRisk = "None";
    if (usesStorage) {
      const hasAnySink = sinksUsed.length > 0;
      const hasAnyEndpoint = endpointsUniq.length > 0;
      if (storageToSink || storageBackedXSSHint || evalWithInput) storageRisk = "Risky";
      else if (!hasAnySink && !hasAnyEndpoint) storageRisk = "Benign";
      else storageRisk = "Potentially risky";
    }

    // Extra pentest flags
    const tabnabbingRisk = hasTabnabbingRisk(src);
    const weakPostMessage = hasWeakPostMessageHandling(src);

    // Badges (only show high-value ones)
    const badges = [];
    if (evalWithInput) badges.push("eval() with dynamic input");
    if (storageToSink) badges.push("storage → sink correlation");
    if (storageBackedXSSHint) badges.push("possible storage-backed XSS");
    if (tabnabbingRisk) badges.push("possible reverse tabnabbing");
    if (weakPostMessage) badges.push("postMessage origin check not obvious");

    return {
      ...fn,
      globalsUsed,
      sourcesUsed,
      sinksUsed,
      endpoints: endpointsUniq,
      storageReads,
      storageWrites,
      storageRisk,
      flags: {
        evalWithInput,
        storageToSink,
        storageBackedXSSHint,
        tabnabbingRisk,
        weakPostMessage
      },
      badges
    };
  });

  /**********************************************************
   * 7) GLOBAL SUMMARY: URLs + risk counts
   **********************************************************/
  const allUrls = uniq(analyzedFunctions.flatMap(f => f.endpoints));

  const summary = {
    totalFunctions: analyzedFunctions.length,
    totalGlobals: globalVars.length,
    totalCookies: cookies.length,
    totalUrls: allUrls.length,
    evalWithInput: analyzedFunctions.filter(f => f.flags.evalWithInput).length,
    storageToSink: analyzedFunctions.filter(f => f.flags.storageToSink).length,
    storageBackedXSSHint: analyzedFunctions.filter(f => f.flags.storageBackedXSSHint).length,
    tabnabbingRisk: analyzedFunctions.filter(f => f.flags.tabnabbingRisk).length,
    weakPostMessage: analyzedFunctions.filter(f => f.flags.weakPostMessage).length,
    storageRisky: analyzedFunctions.filter(f => f.storageRisk === "Risky").length,
    storagePotential: analyzedFunctions.filter(f => f.storageRisk === "Potentially risky").length,
    storageBenign: analyzedFunctions.filter(f => f.storageRisk === "Benign").length,
  };

  /**********************************************************
   * 8) SYNTAX + DANGER HIGHLIGHTING
   **********************************************************/
  const highlightJS = (code) =>
    code
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      // comments
      .replace(/(\/\/.*?$|\/\*[\s\S]*?\*\/)/gm, `<span class="cmt">$1</span>`)
      // strings
      .replace(/(["'`].*?["'`])/g, `<span class="str">$1</span>`)
      // keywords
      .replace(/\b(function|return|if|else|for|while|const|let|var|new|try|catch|throw)\b/g,
        `<span class="kw">$1</span>`)
      // dangerous tokens
      .replace(/\beval\b|\bFunction\b|\binnerHTML\b|\bouterHTML\b|\bdocument\.write\b|\binsertAdjacentHTML\b|\bsetTimeout\b|\bsetInterval\b|\bwindow\.open\b/g,
        `<span class="danger">$&</span>`);

  /**********************************************************
   * 9) BUILD HTML REPORT
   **********************************************************/
  const html = `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>DefenceLogic – Client Exposure Inspector</title>
<style>
body { margin:0; background:#020617; color:#e5e7eb; font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif }
header,footer { padding:20px; border-bottom:1px solid #1e293b }
header h1 { margin:0; color:#38bdf8; font-size:20px }
header p { margin:6px 0 0; color:#94a3b8; font-size:13px }
main { padding:24px; max-width:1500px; margin:auto }

.section { margin-bottom:28px; padding:16px; border:1px solid #1e293b; border-radius:10px }
h2 { margin:0 0 12px; color:#38bdf8; font-size:16px }

.grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px }
.card { border:1px solid #1e293b; border-radius:10px; padding:12px; background:#020617 }
.card .k { color:#94a3b8; font-size:12px }
.card .v { font-weight:700; font-size:18px; margin-top:2px }

table { width:100%; border-collapse:collapse; font-size:13px }
th,td { padding:8px; border-bottom:1px solid #1e293b; text-align:left; vertical-align:top }
th { color:#94a3b8; font-weight:600 }

.fn { border:1px solid #1e293b; border-radius:10px; margin-bottom:18px; overflow:hidden }
.fn-header { padding:10px 14px; color:#38bdf8; font-weight:700; border-bottom:1px solid #1e293b }
.fn-meta { padding:10px 14px; font-size:12px; color:#94a3b8; border-bottom:1px solid #1e293b; line-height:1.5 }
.badges { margin-top:8px }
.badge { display:inline-block; background:#7f1d1d; color:#fecaca; padding:2px 8px; border-radius:999px; font-size:11px; margin-right:6px; margin-bottom:6px }
.badge.alt { background:#1e3a8a; color:#bfdbfe }

pre { margin:0; padding:14px; font-size:12px; white-space:pre-wrap; word-break:break-word }

.kw{color:#7dd3fc} .str{color:#a7f3d0}
.cmt{color:#64748b;font-style:italic}
.danger{color:#f87171;font-weight:800}
.muted{color:#94a3b8;font-size:12px}
</style>
</head>
<body>

<header>
  <h1>DefenceLogic – Client Exposure Inspector</h1>
  <p>Read-only client-side inventory + heuristic analysis (CSP/Trusted Types safe)</p>
</header>

<main>

  <div class="section">
    <h2>Summary</h2>
    <div class="grid">
      <div class="card"><div class="k">Globals</div><div class="v">${summary.totalGlobals}</div></div>
      <div class="card"><div class="k">Accessible Cookies</div><div class="v">${summary.totalCookies}</div></div>
      <div class="card"><div class="k">Functions</div><div class="v">${summary.totalFunctions}</div></div>
      <div class="card"><div class="k">Observed URLs</div><div class="v">${summary.totalUrls}</div></div>
    </div>
    <div class="grid" style="margin-top:12px">
      <div class="card"><div class="k">eval() + dynamic input</div><div class="v">${summary.evalWithInput}</div></div>
      <div class="card"><div class="k">storage → sink</div><div class="v">${summary.storageToSink}</div></div>
      <div class="card"><div class="k">storage-backed XSS hints</div><div class="v">${summary.storageBackedXSSHint}</div></div>
      <div class="card"><div class="k">tabnabbing / postMessage hints</div><div class="v">${summary.tabnabbingRisk + summary.weakPostMessage}</div></div>
    </div>
    <p class="muted" style="margin-top:10px">
      Notes: These are heuristic indicators to guide review. HttpOnly cookies are not accessible via JavaScript.
    </p>
  </div>

  <div class="section">
    <h2>Exposed Global Variables (${globalVars.length})</h2>
    <table>
      <tr><th>Name</th><th>Type</th></tr>
      ${globalVars.map(v => `<tr><td>${v.name}</td><td>${v.type}</td></tr>`).join("")}
    </table>
  </div>

  <div class="section">
    <h2>Accessible Cookies (${cookies.length})</h2>
    <table>
      <tr><th>Name</th><th>Value</th></tr>
      ${cookies.map(c => `<tr><td>${c.name}</td><td>${c.value}</td></tr>`).join("")}
    </table>
    <p class="muted" style="margin-top:8px">HttpOnly cookies are not accessible via JavaScript and are not shown.</p>
  </div>

  <div class="section">
    <h2>Observed Client-Side URLs / Endpoints (${allUrls.length})</h2>
    <table>
      <tr><th>Endpoint</th></tr>
      ${allUrls.map(u => `<tr><td>${u}</td></tr>`).join("")}
    </table>
  </div>

  <div class="section">
    <h2>Exposed Client-Side Functions (${analyzedFunctions.length})</h2>
    ${analyzedFunctions.map(fn => `
      <div class="fn">
        <div class="fn-header">${fn.name}</div>
        <div class="fn-meta">
          <div><b>Storage risk:</b> ${fn.storageRisk}</div>
          <div><b>Globals:</b> ${fn.globalsUsed.join(", ") || "None"}</div>
          <div><b>Sources:</b> ${fn.sourcesUsed.join(", ") || "None"}</div>
          <div><b>Sinks:</b> ${fn.sinksUsed.join(", ") || "None"}</div>
          <div><b>Storage reads:</b> ${fn.storageReads.join(", ") || "None"}</div>
          <div><b>Storage writes:</b> ${fn.storageWrites.join(", ") || "None"}</div>
          <div><b>Endpoints:</b> ${fn.endpoints.join(", ") || "None"}</div>
          ${fn.badges.length ? `<div class="badges">
            ${fn.badges.map(b => `<span class="badge">${b}</span>`).join("")}
          </div>` : ""}
        </div>
        <pre>${highlightJS(fn.source)}</pre>
      </div>
    `).join("")}
  </div>

</main>

<footer>
  Generated by DefenceLogic · Client-side inspection only · No server interaction
</footer>

</body>
</html>
`;

  /**********************************************************
   * 10) RENDER + EXPORT JSON
   **********************************************************/
  safeRenderHTML(html);

  try {
    const blob = new Blob(
      [JSON.stringify({ summary, globalVars, cookies, urls: allUrls, functions: analyzedFunctions }, null, 2)],
      { type: "application/json" }
    );
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "defencelogic_client_exposure.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    console.log("[+] JSON exported: defencelogic_client_exposure.json");
  } catch (e) {
    console.warn("[!] JSON export failed:", e);
  }
})();

