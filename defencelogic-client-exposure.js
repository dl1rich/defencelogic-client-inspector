(() => {
  try {
    // DefenceLogic Client Exposure Inspector
    // Read-only client-side analysis
    // Version: 1.1 (hardened)

    if (window.__DEFENCELOGIC_INSPECTOR_LOADED__) {
      console.warn("DefenceLogic Inspector already loaded");
      return;
    }
    window.__DEFENCELOGIC_INSPECTOR_LOADED__ = true;

    /**********************************************************
     * SAFE HELPERS
     **********************************************************/
    const uniq = (arr) => [...new Set(arr)].filter(Boolean);

    const safe = (fn, fallback) => {
      try { return fn(); } catch (e) {
        console.warn("[!] Blocked:", e.message);
        return fallback;
      }
    };

    const safeTypeof = (obj, key) => {
      try { return typeof obj[key]; } catch { return "unreadable"; }
    };

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
     * 1) GLOBAL VARIABLES
     **********************************************************/
    const globalVars = safe(() =>
      Object.keys(window)
        .filter(k => {
          try {
            return typeof window[k] !== "function" && k !== "window" && k !== "document";
          } catch { return false; }
        })
        .map(name => ({ name, type: safeTypeof(window, name) }))
    , []);

    const globalVarNames = globalVars.map(v => v.name);

    /**********************************************************
     * 2) ACCESSIBLE COOKIES (non-HttpOnly)
     **********************************************************/
    const cookies = safe(() => {
      if (typeof document === "undefined" || typeof document.cookie !== "string") return [];
      return document.cookie
        ? document.cookie.split(";").map(c => {
            const [name, ...rest] = c.trim().split("=");
            return { name, value: rest.join("=") };
          })
        : [];
    }, []);

    /**********************************************************
     * 3) GLOBAL FUNCTIONS (non-native)
     **********************************************************/
    const functions = safe(() =>
      Object.keys(window)
        .filter(k => {
          try { return typeof window[k] === "function"; }
          catch { return false; }
        })
        .map(name => {
          let source = "[unreadable]";
          try {
            source = Function.prototype.toString.call(window[name]);
          } catch {}
          return { name, source };
        })
        .filter(f => !f.source.includes("[native code]"))
    , []);

    /**********************************************************
     * 4) HEURISTICS
     **********************************************************/
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

    const SINK_PATTERNS = [
      { label: "innerHTML", regex: /\.innerHTML\s*=/ },
      { label: "outerHTML", regex: /\.outerHTML\s*=/ },
      { label: "insertAdjacentHTML", regex: /\.insertAdjacentHTML\s*\(/ },
      { label: "document.write()", regex: /\bdocument\.write\s*\(/ },
      { label: "eval()", regex: /\beval\s*\(/ },
      { label: "Function()", regex: /\bnew\s+Function\b|\bFunction\s*\(/ },
      { label: "setTimeout(string)", regex: /\bsetTimeout\s*\(\s*['"`]/ },
      { label: "setInterval(string)", regex: /\bsetInterval\s*\(\s*['"`]/ },
      { label: "location assignment", regex: /\blocation\s*=/ },
      { label: "window.open()", regex: /\bwindow\.open\s*\(/ },
    ];

    const ENDPOINT_REGEXES = [
      /fetch\s*\(\s*(['"`])(.*?)\1/gi,
      /open\s*\(\s*(['"`])(.*?)\1/gi,
      /url\s*:\s*(['"`])(.*?)\1/gi,
      /(['"`])(\/api\/[a-zA-Z0-9/_-]+)\1/gi,
      /(['"`])(\/[a-zA-Z0-9/_-]+\.php(?:\?.*?)?)\1/gi,
    ];

    const STORAGE_READ_PATTERNS = [
      { label: "localStorage.getItem", regex: /\blocalStorage\.getItem\s*\(/ },
      { label: "sessionStorage.getItem", regex: /\bsessionStorage\.getItem\s*\(/ },
      { label: "document.cookie (read)", regex: /\bdocument\.cookie\b/ },
    ];

    const STORAGE_WRITE_PATTERNS = [
      { label: "localStorage.setItem", regex: /\blocalStorage\.setItem\s*\(/ },
      { label: "sessionStorage.setItem", regex: /\bsessionStorage\.setItem\s*\(/ },
      { label: "document.cookie (write)", regex: /\bdocument\.cookie\s*=/ },
    ];

    const hasTabnabbingRisk = (src) =>
      /\bwindow\.open\s*\(/.test(src) &&
      !/\bnoopener\b|\bnoreferrer\b/i.test(src);

    const hasWeakPostMessageHandling = (src) =>
      (/\baddEventListener\s*\(\s*['"]message['"]/.test(src) || /\bonmessage\b/.test(src)) &&
      !/\borigin\b/.test(src);

    /**********************************************************
     * 5) ANALYSIS
     **********************************************************/
    const analyzedFunctions = functions.map(fn => {
      const src = fn.source;

      const globalsUsed = globalVarNames.filter(v => new RegExp(`\\b${v}\\b`).test(src));
      const sourcesUsed = SOURCE_PATTERNS.filter(p => p.regex.test(src)).map(p => p.label);
      const sinksUsed = SINK_PATTERNS.filter(p => p.regex.test(src)).map(p => p.label);
      const storageReads = STORAGE_READ_PATTERNS.filter(p => p.regex.test(src)).map(p => p.label);
      const storageWrites = STORAGE_WRITE_PATTERNS.filter(p => p.regex.test(src)).map(p => p.label);

      const endpoints = [];
      ENDPOINT_REGEXES.forEach(rgx => {
        let m;
        while ((m = rgx.exec(src)) !== null) {
          if (m[2] && !m[2].startsWith("javascript:")) endpoints.push(m[2]);
        }
      });

      const hasEval = /\beval\s*\(|\bFunction\s*\(/.test(src);
      const hasDynamicInput = /\+|\$\{|\bvalue\b|\barguments\b/.test(src);

      const evalWithInput = hasEval && hasDynamicInput;
      const storageToSink = storageReads.length &&
        /(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|Function)/.test(src);

      const storageBackedXSSHint = storageToSink && /(getItem|document\.cookie)/.test(src);

      let storageRisk = "None";
      if (storageReads.length || storageWrites.length) {
        if (storageBackedXSSHint || evalWithInput) storageRisk = "Risky";
        else if (!sinksUsed.length) storageRisk = "Benign";
        else storageRisk = "Potentially risky";
      }

      const badges = [];
      if (evalWithInput) badges.push("eval() with dynamic input");
      if (storageToSink) badges.push("storage → sink");
      if (storageBackedXSSHint) badges.push("possible storage-backed XSS");
      if (hasTabnabbingRisk(src)) badges.push("possible reverse tabnabbing");
      if (hasWeakPostMessageHandling(src)) badges.push("weak postMessage handling");

      return {
        name: fn.name,
        source: fn.source,
        globalsUsed,
        sourcesUsed,
        sinksUsed,
        storageReads,
        storageWrites,
        endpoints: uniq(endpoints),
        storageRisk,
        badges
      };
    });

    /**********************************************************
     * 6) SUMMARY
     **********************************************************/
    const allUrls = uniq(analyzedFunctions.flatMap(f => f.endpoints));

    const summary = {
      globals: globalVars.length,
      cookies: cookies.length,
      functions: analyzedFunctions.length,
      urls: allUrls.length
    };

    /**********************************************************
     * 7) OUTPUT (HTML + JSON)
     **********************************************************/
    const html = `
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>DefenceLogic – Client Exposure Inspector</title>
<style>
body{background:#020617;color:#e5e7eb;font-family:system-ui;padding:20px}
h1,h2{color:#38bdf8}
pre{background:#020617;border:1px solid #1e293b;padding:12px;overflow:auto}
.badge{display:inline-block;background:#7f1d1d;color:#fecaca;padding:2px 8px;border-radius:999px;font-size:11px;margin-right:6px}
</style>
</head>
<body>
<h1>DefenceLogic – Client Exposure Inspector</h1>
<h2>Summary</h2>
<pre>${JSON.stringify(summary,null,2)}</pre>
<h2>Functions</h2>
${analyzedFunctions.map(f => `
<h3>${f.name}</h3>
${f.badges.map(b=>`<span class="badge">${b}</span>`).join("")}
<pre>${f.source.replace(/</g,"&lt;")}</pre>
`).join("")}
</body>
</html>
`;

    safeRenderHTML(html);

    safe(() => {
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
    });

    console.log("[+] DefenceLogic Inspector completed safely");

  } catch (fatal) {
    console.error("[!] DefenceLogic Inspector fatal error:", fatal);
    alert("DefenceLogic Inspector failed gracefully. See console for details.");
  }
})();
