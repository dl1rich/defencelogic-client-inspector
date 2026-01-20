(() => {
  try {
    if (window.__DEFENCELOGIC_INSPECTOR_LOADED__) return;
    window.__DEFENCELOGIC_INSPECTOR_LOADED__ = true;

    /**********************************************************
     * ENVIRONMENT STATE
     **********************************************************/
    const environment = {
      sandboxed: false,
      cookieBlocked: false,
      popupBlocked: false,
      blobBlocked: false,
      notes: []
    };

    /**********************************************************
     * HELPERS
     **********************************************************/
    const uniq = a => [...new Set(a)].filter(Boolean);

    const safe = (fn, fb) => {
      try { return fn(); } catch { return fb; }
    };

    /**********************************************************
     * SYNTAX HIGHLIGHTING
     **********************************************************/
    const highlightJS = (code) =>
      code
        .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
        .replace(/(\/\/.*?$|\/\*[\s\S]*?\*\/)/gm,'<span class="cmt">$1</span>')
        .replace(/(["'`].*?["'`])/g,'<span class="str">$1</span>')
        .replace(/\b(class|function|return|if|else|for|while|const|let|var|new|try|catch|throw|extends)\b/g,
          '<span class="kw">$1</span>')
        .replace(/\beval\b|\bFunction\b|\binnerHTML\b|\bouterHTML\b|\bdocument\.write\b|\binsertAdjacentHTML\b|\bwindow\.open\b/g,
          '<span class="danger">$&</span>');

    /**********************************************************
     * CLASS PARSER (key fix)
     **********************************************************/
    const extractClassesAndMethods = (src) => {
      const classes = [];
      const classRegex = /class\s+([A-Za-z0-9_$]+)[\s\S]*?{([\s\S]*?)^}/gm;
      let m;

      while ((m = classRegex.exec(src)) !== null) {
        const className = m[1];
        const body = m[2];

        const methods = [];
        const methodRegex = /^\s*([a-zA-Z0-9_$]+)\s*\((.*?)\)\s*{/gm;
        let mm;

        while ((mm = methodRegex.exec(body)) !== null) {
          methods.push({
            name: mm[1],
            source: mm[0]
          });
        }

        classes.push({ className, methods, raw: src });
      }
      return classes;
    };

    /**********************************************************
     * GLOBAL FUNCTIONS / CLASSES
     **********************************************************/
    const globals = safe(() =>
      Object.keys(window)
        .filter(k => typeof window[k] === "function")
        .map(name => {
          let src = "[unreadable]";
          try { src = Function.prototype.toString.call(window[name]); } catch {}
          return { name, src };
        })
    , []);

    /**********************************************************
     * ANALYSIS (shared)
     **********************************************************/
    const analyzeSource = (src) => {
      const flags = [];
      if (/\beval\s*\(/.test(src)) flags.push("eval()");
      if (/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(src))
        flags.push("DOM sink");
      if (/localStorage|getItem|sessionStorage|document\.cookie/.test(src))
        flags.push("storage access");
      if (/fetch\s*\(|\/api\//.test(src))
        flags.push("endpoint usage");
      return flags;
    };

    /**********************************************************
     * BUILD HTML
     **********************************************************/
    let html = `
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>DefenceLogic – Client Exposure Inspector</title>
<style>
body{background:#020617;color:#e5e7eb;font-family:system-ui;padding:20px}
h1,h2,h3{color:#38bdf8}
.section{border:1px solid #1e293b;border-radius:10px;padding:16px;margin-bottom:20px}
pre{background:#020617;border:1px solid #1e293b;padding:12px;white-space:pre-wrap}
.kw{color:#7dd3fc}.str{color:#a7f3d0}.cmt{color:#64748b;font-style:italic}
.danger{color:#f87171;font-weight:700}
.badge{display:inline-block;background:#7f1d1d;color:#fecaca;padding:2px 8px;border-radius:999px;font-size:11px;margin-right:6px}
</style>
</head>
<body>
<h1>DefenceLogic – Client Exposure Inspector</h1>
<div class="section"><h2>Client-Side Code Structure</h2>
`;

    globals.forEach(g => {
      const classes = extractClassesAndMethods(g.src);

      if (classes.length) {
        classes.forEach(cls => {
          html += `<h3>Class: ${cls.className}</h3>`;
          cls.methods.forEach(m => {
            const flags = analyzeSource(m.source);
            html += `
              <div>
                <b>Method:</b> ${m.name}
                ${flags.map(f=>`<span class="badge">${f}</span>`).join("")}
                <pre>${highlightJS(m.source)}</pre>
              </div>`;
          });
        });
      } else {
        const flags = analyzeSource(g.src);
        html += `
          <h3>Function: ${g.name}</h3>
          ${flags.map(f=>`<span class="badge">${f}</span>`).join("")}
          <pre>${highlightJS(g.src)}</pre>`;
      }
    });

    html += `
</div>
</body>
</html>`;

    /**********************************************************
     * RENDER
     **********************************************************/
    try {
      const w = window.open("about:blank", "_blank");
      if (w && w.document) {
        w.document.write(html);
        w.document.close();
      }
    } catch {}

  } catch (e) {
    console.error("Inspector failed safely:", e);
  }
})();
