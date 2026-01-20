(() => {
  try {
    // ======================================================
    // DefenceLogic – Client Exposure Inspector
    // Read-only client-side analysis
    // Version: 1.3 (consolidated / syntax restored)
    // ======================================================

    if (window.__DEFENCELOGIC_INSPECTOR_LOADED__) return;
    window.__DEFENCELOGIC_INSPECTOR_LOADED__ = true;

    /**********************************************************
     * ENVIRONMENT STATE (quiet, reportable)
     **********************************************************/
    const environment = {
      sandboxed: false,
      cookieBlocked: false,
      popupBlocked: false,
      blobBlocked: false,
      notes: []
    };

    /**********************************************************
     * SAFE HELPERS
     **********************************************************/
    const uniq = (arr) => [...new Set(arr)].filter(Boolean);

    const safe = (fn, fallback) => {
      try { return fn(); }
      catch (e) {
        environment.notes.push(e.message);
        return fallback;
      }
    };

    const safeTypeof = (obj, key) => {
      try { return typeof obj[key]; }
      catch { return "unreadable"; }
    };

    /**********************************************************
     * SAFE RENDERING (CSP / sandbox tolerant)
     **********************************************************/
    const safeRenderHTML = (html) => {
      try {
        const w = window.open("about:blank", "_blank");
        if (w && w.document) {
          w.document.open();
          w.document.write(html);
          w.document.close();
          return;
        }
        throw new Error("Popup blocked");
      } catch {
        environment.popupBlocked = true;
        environment.sandboxed = true;
      }

      try {
        const blob = new Blob([html], { type: "text/html" });
        const url = URL.createObjectURL(blob);
        const w = window.open(url, "_blank");
        if (!w) throw new Error("Blob popup blocked");
        return;
      } catch {
        environment.blobBlocked = true;
        environment.sandboxed = true;
      }
    };

    /**********************************************************
     * 1) GLOBAL VARIABLES
     **********************************************************/
    const globalVars = safe(() =>
      Object.keys(window)
        .filter(k => {
          try {
            return typeof window[k] !== "function" &&
                   k !== "window" &&
                   k !== "document";
          } catch { return false; }
        })
        .map(name => ({ name, type: safeTypeof(window, name) }))
    , []);

    const globalVarNames = globalVars.map(v => v.name);

    /**********************************************************
     * 2) ACCESSIBLE COOKIES (fail-soft)
     **********************************************************/
    const cookies = safe(() => {
      try {
        const c = document.cookie;
        return c
          ? c.split(";").map(v => {
              const [name, ...rest] = v.trim().split("=");
              return { name, value: rest.join("=") };
            })
          : [];
      } catch {
        environment.cookieBlocked = true;
        environment.sandboxed = true;
        environment.notes.push("Cookie access blocked by sandbox or origin policy");
        return [];
      }
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
     * 4) HEURISTIC PATTERNS
     **********************************************************/
    const SOURCE_PATTERNS = [
      { label: "location.search", regex: /\blocation\.search\b/ },
      { label: "location.hash", regex: /\blocation\.hash\b/ },
      { label: "document.cookie", regex: /\bdocument\.cookie\b/ },
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
      { label: "Function()", regex: /\bFunction\s*\(/ },
      { label: "setTimeout(string)", regex: /\bsetTimeout\s*\(\s*['"`]/ },
      { label: "setInterval(string)", regex: /\bsetInterval\s*\(\s*['"`]/ },
      { label: "window.open()", regex: /\bwindow\.open\s*\(/ },
    ];

    const ENDPOINT_REGEXES = [
      /fetch\s*\(\s*['"`](.*?)['"`]/gi,
      /open\s*\(\s*['"`](.*?)['"`]/gi,
      /url\s*:\s*['"`](.*?)['"`]/gi,
      /(['"`])(\/api\/[a-zA-Z0-9/_-]+)\1/gi,
      /(['"`])(\/[a-zA-Z0-9/_-]+\.php(?:\?.*?)?)\1/gi,
      /(['"`])(\/[a-zA-Z0-9/_-]+\.json(?:\?.*?)?)\1/gi,
    ];

    /**********************************************************
     * 5) FUNCTION ANALYSIS
     **********************************************************/
    const analyzedFunctions = functions.map(fn => {
      const src = fn.source;

      const globalsUsed = globalVarNames.filter(v => new RegExp(`\\b${v}\\b`).test(src));
      const sourcesUsed = SOURCE_PATTERNS.filter(p => p.regex.test(src)).map(p => p.label);
      const sinksUsed = SINK_PATTERNS.filter(p => p.regex.test(src)).map(p => p.label);

      const endpoints = [];
      ENDPOINT_REGEXES.forEach(r => {
        let m;
        while ((m = r.exec(src)) !== null) endpoints.push(m[1] || m[2]);
      });

      const hasEval = /\beval\s*\(|\bFunction\s*\(/.test(src);
      const hasDynamicInput = /\+|\$\{|\bvalue\b|\barguments\b/.test(src);

      const storageToSink =
        /(localStorage|getItem|sessionStorage|document\.cookie)/.test(src) &&
        /(innerHTML|outerHTML|insertAdjacentHTML|eval|document\.write)/.test(src);

      const badges = [];
      if (hasEval && hasDynamicInput) badges.push("eval() with dynamic input");
      if (storageToSink) badges.push("storage → sink correlation");
      if (/window\.open\s*\(/.test(src) && !/noopener|noreferrer/i.test(src))
        badges.push("possible reverse tabnabbing");
      if (
        /(addEventListener\s*\(\s*['"]message['"]|onmessage)/.test(src) &&
        !/origin/.test(src)
      )
        badges.push("weak postMessage origin handling");

      return {
        name: fn.name,
        source: fn.source,
        globalsUsed,
        sourcesUsed,
        sinksUsed,
        endpoints: uniq(endpoints),
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
     * 7) SYNTAX HIGHLIGHTING
     **********************************************************/
    const highlightJS = (code) =>
      code
        .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
        .replace(/(\/\/.*?$|\/\*[\s\S]*?\*\/)/gm,'<span class="cmt">$1</span>')
        .replace(/(["'`].*?["'`])/g,'<span class="str">$1</span>')
        .replace(/\b(function|return|if|else|for|while|const|let|var|new|try|catch|throw)\b/g,'<span class="kw">$1</span>')
        .replace(/\beval\b|\bFunction\b|\binnerHTML\b|\bouterHTML\b|\bdocument\.write\b|\binsertAdjacentHTML\b|\bwindow\.open\b/g,'<span class="danger">$&</span>');

    /**********************************************************
     * 8) HTML REPORT
     **********************************************************/
    const html = `
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>DefenceLogic – Client Exposure Inspector</title>
<style>
body{background:#020617;color:#e5e7eb;font-family:system-ui;padding:20px}
h1,h2,h3{color:#38bdf8}
.section{border:1px solid #1e293b;border-radius:10px;padding:16px;margin-bottom:20px}
.badge{display:inline-block;background:#7f1d1d;color:#fecaca;padding:2px 8px;border-radius:999px;font-size:11px;margin-right:6px}
.ok{color:#86efac}.warn{color:#fde68a}.muted{color:#94a3b8}
pre{background:#020617;border:1px solid #1e293b;padding:12px;white-space:pre-wrap}
.kw{color:#7dd3fc}.str{color:#a7f3d0}.cmt{color:#64748b;font-style:italic}
.danger{color:#f87171;font-weight:700}
</style>
</head>
<body>

<h1>DefenceLogic – Client Exposure Inspector</h1>

<div class="section">
<h2>Execution Environment</h2>
${environment.sandboxed
  ? `<p class="warn">Execution occurred in a restricted browser context.</p>
     <ul>
       ${environment.cookieBlocked ? "<li>Cookie access blocked</li>" : ""}
       ${environment.popupBlocked ? "<li>Popup rendering blocked</li>" : ""}
       ${environment.blobBlocked ? "<li>Blob rendering blocked</li>" : ""}
     </ul>`
  : `<p class="ok">No browser-level execution restrictions detected.</p>`}
</div>

<div class="section">
<h2>Summary</h2>
<pre>${JSON.stringify(summary,null,2)}</pre>
</div>

<div class="section">
<h2>Exposed Client-Side Functions</h2>
${analyzedFunctions.map(f => `
<h3>${f.name}</h3>
${f.badges.map(b=>`<span class="badge">${b}</span>`).join("")}
<pre>${highlightJS(f.source)}</pre>
`).join("")}
</div>

<div class="section">
<h2>TODO / Future Enhancements</h2>
<ul class="muted">
<li>Confirm coverage of all storage-backed DOM flows</li>
<li>Add iframe sandbox attribute introspection</li>
<li>Add optional Markdown report export</li>
<li>Review coverage against latest DOM XSS research</li>
<li>Evaluate lightweight taint-style correlation</li>
</ul>
</div>

</body>
</html>
`;

    safeRenderHTML(html);

    /**********************************************************
     * 9) JSON EXPORT
     **********************************************************/
    safe(() => {
      const blob = new Blob(
        [JSON.stringify({
          summary,
          environment,
          globalVars,
          cookies,
          urls: allUrls,
          functions: analyzedFunctions
        }, null, 2)],
        { type: "application/json" }
      );
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "defencelogic_client_exposure.json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    });

  } catch (fatal) {
    console.error("DefenceLogic Inspector failed safely:", fatal);
  }
})();
