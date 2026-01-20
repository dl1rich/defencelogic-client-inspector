(() => {
  // START - Show immediate visual feedback
  console.log("%c🔍 DefenceLogic Inspector Started", "color:#38bdf8;font-size:16px;font-weight:bold");
  console.log("%cAnalyzing " + window.location.href, "color:#94a3b8");
  
  try {
    if (window.__DEFENCELOGIC_INSPECTOR_LOADED__) {
      console.warn("Inspector already running. Reload page to run again.");
      return;
    }
    window.__DEFENCELOGIC_INSPECTOR_LOADED__ = true;

    /**********************************************************
     * HELPERS
     **********************************************************/
    const uniq = a => [...new Set(a)].filter(Boolean);

    const safe = (fn, fb) => {
      try { return fn(); } catch { return fb; }
    };

    const escapeHtml = (str) => String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");

    /**********************************************************
     * SITE INFORMATION GATHERING
     **********************************************************/
    const getSiteInfo = () => {
      const info = {
        url: window.location.href,
        protocol: window.location.protocol,
        hostname: window.location.hostname,
        port: window.location.port || 'default',
        pathname: window.location.pathname,
        origin: window.location.origin,
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        cookiesEnabled: navigator.cookieEnabled,
        onLine: navigator.onLine,
        viewport: `${window.innerWidth}x${window.innerHeight}`,
        screenResolution: `${screen.width}x${screen.height}`,
        colorDepth: screen.colorDepth,
        documentTitle: document.title,
        referrer: document.referrer || 'Direct',
        charset: document.characterSet,
        readyState: document.readyState,
        domain: document.domain,
        frameCount: window.frames.length,
        hasServiceWorker: 'serviceWorker' in navigator,
        hasWebWorker: typeof Worker !== 'undefined',
        hasWebSocket: typeof WebSocket !== 'undefined',
        hasIndexedDB: typeof indexedDB !== 'undefined',
        hasGeolocation: 'geolocation' in navigator,
        hasNotifications: 'Notification' in window
      };

      // Check for security headers (limited client-side visibility)
      info.csp = safe(() => {
        const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        return meta ? meta.getAttribute('content') : 'Not set via meta tag';
      }, 'Unknown');

      // Detect frameworks
      info.frameworks = [];
      if (window.React) info.frameworks.push('React');
      if (window.Angular) info.frameworks.push('Angular');
      if (window.Vue) info.frameworks.push('Vue.js');
      if (window.jQuery) info.frameworks.push('jQuery ' + (window.jQuery.fn?.jquery || ''));
      if (window.Backbone) info.frameworks.push('Backbone');
      if (window.ember) info.frameworks.push('Ember');
      if (window.Svelte) info.frameworks.push('Svelte');
      if (window.next) info.frameworks.push('Next.js');
      if (window.__NUXT__) info.frameworks.push('Nuxt.js');
      if (window.Alpine) info.frameworks.push('Alpine.js');

      // Check for common analytics/tracking
      info.tracking = [];
      if (window.ga || window.google_tag_manager) info.tracking.push('Google Analytics/GTM');
      if (window.fbq) info.tracking.push('Facebook Pixel');
      if (window.mixpanel) info.tracking.push('Mixpanel');
      if (window.amplitude) info.tracking.push('Amplitude');
      if (window._paq) info.tracking.push('Matomo');
      if (window.hj) info.tracking.push('Hotjar');
      if (window.gtag) info.tracking.push('Google Tag');
      
      return info;
    };

    /**********************************************************
     * ADVANCED SECURITY CHECKS
     **********************************************************/
    const performSecurityChecks = () => {
      const checks = [];

      // Check for HTTPS
      if (window.location.protocol === 'http:') {
        checks.push({
          severity: 'HIGH',
          category: 'Transport Security',
          issue: 'Site not using HTTPS - traffic is unencrypted',
          recommendation: 'Implement HTTPS with valid TLS certificate'
        });
      }

      // Check for mixed content
      const resources = safe(() => performance.getEntriesByType('resource'), []);
      const insecureResources = resources.filter(r => r.name.startsWith('http://'));
      if (insecureResources.length > 0 && window.location.protocol === 'https:') {
        checks.push({
          severity: 'HIGH',
          category: 'Mixed Content',
          issue: `${insecureResources.length} HTTP resources loaded on HTTPS page`,
          recommendation: 'Load all resources over HTTPS'
        });
      }

      // Check for iframe usage
      const iframes = document.querySelectorAll('iframe');
      if (iframes.length > 0) {
        const unsafeIframes = Array.from(iframes).filter(f => !f.hasAttribute('sandbox'));
        if (unsafeIframes.length > 0) {
          checks.push({
            severity: 'MEDIUM',
            category: 'Iframe Security',
            issue: `${unsafeIframes.length} iframes without sandbox attribute`,
            recommendation: 'Use sandbox attribute on iframes to restrict capabilities'
          });
        }
      }

      // Check for forms without HTTPS action
      const forms = document.querySelectorAll('form');
      const insecureForms = Array.from(forms).filter(f => {
        const action = f.getAttribute('action');
        return action && action.startsWith('http://');
      });
      if (insecureForms.length > 0) {
        checks.push({
          severity: 'HIGH',
          category: 'Form Security',
          issue: `${insecureForms.length} forms submitting to HTTP URLs`,
          recommendation: 'All form submissions should use HTTPS'
        });
      }

      // Check for autocomplete on sensitive inputs
      const passwordInputs = document.querySelectorAll('input[type="password"]');
      const autocompleteOn = Array.from(passwordInputs).filter(i => 
        i.getAttribute('autocomplete') !== 'off' && 
        i.getAttribute('autocomplete') !== 'new-password'
      );
      if (autocompleteOn.length > 0) {
        checks.push({
          severity: 'LOW',
          category: 'Form Security',
          issue: 'Password fields may have autocomplete enabled',
          recommendation: 'Consider using autocomplete="new-password" for sensitive fields'
        });
      }

      // Check for external scripts
      const scripts = document.querySelectorAll('script[src]');
      const externalScripts = Array.from(scripts).filter(s => {
        const src = s.getAttribute('src');
        return src && !src.startsWith('/') && !src.includes(window.location.hostname);
      });
      if (externalScripts.length > 0) {
        const withoutIntegrity = externalScripts.filter(s => !s.hasAttribute('integrity'));
        if (withoutIntegrity.length > 0) {
          checks.push({
            severity: 'MEDIUM',
            category: 'Script Integrity',
            issue: `${withoutIntegrity.length} external scripts without SRI (Subresource Integrity)`,
            recommendation: 'Add integrity attributes to external scripts'
          });
        }
      }

      // Check for localStorage/sessionStorage with sensitive data
      const storageKeys = [];
      safe(() => {
        for (let i = 0; i < localStorage.length; i++) {
          storageKeys.push(localStorage.key(i).toLowerCase());
        }
      });
      safe(() => {
        for (let i = 0; i < sessionStorage.length; i++) {
          storageKeys.push(sessionStorage.key(i).toLowerCase());
        }
      });
      
      const sensitivePatterns = ['token', 'auth', 'session', 'key', 'password', 'secret', 'api'];
      const hasSensitiveStorage = storageKeys.some(k => 
        sensitivePatterns.some(p => k.includes(p))
      );
      
      if (hasSensitiveStorage) {
        checks.push({
          severity: 'MEDIUM',
          category: 'Data Storage',
          issue: 'Potentially sensitive data stored in localStorage/sessionStorage',
          recommendation: 'Consider using HttpOnly cookies or secure server-side sessions for sensitive data'
        });
      }

      // Check for console logging in production
      const hasConsoleLog = safe(() => {
        return Array.from(document.querySelectorAll('script:not([src])')).some(s => 
          /console\.(log|debug|info)/.test(s.textContent)
        );
      }, false);
      
      if (hasConsoleLog) {
        checks.push({
          severity: 'LOW',
          category: 'Information Disclosure',
          issue: 'Console logging detected in inline scripts',
          recommendation: 'Remove debug logging in production'
        });
      }

      // Check for missing security-related meta tags
      const hasXFrameOptions = document.querySelector('meta[http-equiv="X-Frame-Options"]');
      if (!hasXFrameOptions && iframes.length === 0) {
        checks.push({
          severity: 'MEDIUM',
          category: 'Clickjacking Protection',
          issue: 'No X-Frame-Options header set (check server headers)',
          recommendation: 'Set X-Frame-Options or use CSP frame-ancestors directive'
        });
      }

      return checks;
    };

    /**********************************************************
     * SYNTAX HIGHLIGHTING - Proper character-by-character parser
     **********************************************************/
    const highlightJS = (code) => {
      const keywords = new Set(['class', 'function', 'return', 'if', 'else', 'for', 'while', 'const', 'let', 'var', 'new', 'try', 'catch', 'throw', 'extends', 'async', 'await']);
      const dangerous = new Set(['eval', 'Function', 'innerHTML', 'outerHTML']);
      
      let result = '';
      let i = 0;
      const len = code.length;
      
      while (i < len) {
        const ch = code[i];
        
        // Check for comments first
        if (ch === '/' && i + 1 < len) {
          if (code[i + 1] === '/') {
            // Single-line comment
            let comment = '//';
            i += 2;
            while (i < len && code[i] !== '\n') {
              comment += code[i++];
            }
            result += '<span class="cmt">' + escapeHtml(comment) + '</span>';
            continue;
          } else if (code[i + 1] === '*') {
            // Multi-line comment
            let comment = '/*';
            i += 2;
            while (i < len - 1) {
              comment += code[i];
              if (code[i] === '*' && code[i + 1] === '/') {
                comment += '/';
                i += 2;
                break;
              }
              i++;
            }
            result += '<span class="cmt">' + escapeHtml(comment) + '</span>';
            continue;
          }
        }
        
        // Check for strings
        if (ch === '"' || ch === "'" || ch === '`') {
          const quote = ch;
          let str = quote;
          i++;
          while (i < len) {
            const c = code[i];
            str += c;
            if (c === '\\' && i + 1 < len) {
              // Escape sequence
              str += code[i + 1];
              i += 2;
            } else if (c === quote) {
              i++;
              break;
            } else {
              i++;
            }
          }
          result += '<span class="str">' + escapeHtml(str) + '</span>';
          continue;
        }
        
        // Check for identifiers/keywords
        if (/[a-zA-Z_$]/.test(ch)) {
          let identifier = ch;
          i++;
          while (i < len && /[a-zA-Z0-9_$]/.test(code[i])) {
            identifier += code[i++];
          }
          
          if (dangerous.has(identifier)) {
            result += '<span class="danger">' + escapeHtml(identifier) + '</span>';
          } else if (keywords.has(identifier)) {
            result += '<span class="kw">' + escapeHtml(identifier) + '</span>';
          } else {
            result += escapeHtml(identifier);
          }
          continue;
        }
        
        // Check for dangerous property access patterns
        if (ch === '.' && i + 1 < len) {
          const remaining = code.substring(i + 1);
          if (remaining.startsWith('innerHTML') || remaining.startsWith('outerHTML')) {
            const prop = remaining.startsWith('innerHTML') ? 'innerHTML' : 'outerHTML';
            result += escapeHtml('.') + '<span class="danger">' + escapeHtml(prop) + '</span>';
            i += 1 + prop.length;
            continue;
          }
        }
        
        // Regular character
        result += escapeHtml(ch);
        i++;
      }
      
      return result;
    };

    /**********************************************************
     * NATIVE CODE DETECTION
     **********************************************************/
    const isNativeCode = (src) => {
      return /\[native code\]/.test(src) || src === "[unreadable]";
    };

    /**********************************************************
     * CLASS PARSER
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
        .filter(k => {
          try {
            return typeof window[k] === "function" && k !== '__DEFENCELOGIC_INSPECTOR_LOADED__';
          } catch {
            return false;
          }
        })
        .map(name => {
          let src = "[unreadable]";
          try { 
            src = Function.prototype.toString.call(window[name]); 
          } catch {}
          return { name, src };
        })
    , []);

    /**********************************************************
     * COOKIES ANALYSIS
     **********************************************************/
    const getCookies = () => {
      return safe(() => {
        const cookieStr = document.cookie;
        if (!cookieStr) return [];
        
        return cookieStr.split(';').map(c => {
          const [name, ...valueParts] = c.split('=');
          const value = valueParts.join('=');
          return {
            name: name.trim(),
            value: value.trim(),
            length: value.length
          };
        });
      }, []);
    };

    /**********************************************************
     * LOCAL/SESSION STORAGE ANALYSIS
     **********************************************************/
    const getStorageData = () => {
      const data = { localStorage: [], sessionStorage: [] };
      
      safe(() => {
        for (let i = 0; i < localStorage.length; i++) {
          const key = localStorage.key(i);
          const value = localStorage.getItem(key);
          data.localStorage.push({ key, value, length: value?.length || 0 });
        }
      });

      safe(() => {
        for (let i = 0; i < sessionStorage.length; i++) {
          const key = sessionStorage.key(i);
          const value = sessionStorage.getItem(key);
          data.sessionStorage.push({ key, value, length: value?.length || 0 });
        }
      });

      return data;
    };

    /**********************************************************
     * GLOBAL VARIABLES ANALYSIS
     **********************************************************/
    const getGlobalVars = () => {
      return safe(() => {
        const natives = new Set(['window', 'document', 'navigator', 'location', 'history', 
          'console', 'alert', 'confirm', 'prompt', 'setTimeout', 'setInterval', 
          'clearTimeout', 'clearInterval', 'fetch', 'XMLHttpRequest', 'localStorage',
          'sessionStorage', 'IndexedDB', 'crypto', 'performance', 'screen', 'frames']);

        return Object.keys(window)
          .filter(k => {
            try {
              return typeof window[k] !== "function" && 
                     !natives.has(k) && 
                     !k.startsWith('__') &&
                     k !== '__DEFENCELOGIC_INSPECTOR_LOADED__';
            } catch {
              return false;
            }
          })
          .map(name => {
            let type = 'unknown';
            let value = '[unreadable]';
            try {
              type = typeof window[name];
              if (type === 'object' && window[name] === null) {
                value = 'null';
              } else if (type === 'object' || type === 'array') {
                value = JSON.stringify(window[name], null, 2).substring(0, 200);
              } else {
                value = String(window[name]).substring(0, 200);
              }
            } catch {}
            return { name, type, value };
          });
      }, []);
    };

    /**********************************************************
     * ANALYSIS (shared)
     **********************************************************/
    const analyzeSource = (src) => {
      const flags = [];
      const risks = [];
      
      // High risk patterns
      if (/\beval\s*\(/.test(src)) {
        flags.push("eval()");
        risks.push({ severity: "HIGH", issue: "eval() detected - potential code injection" });
      }
      if (/new\s+Function\s*\(/.test(src)) {
        flags.push("Function constructor");
        risks.push({ severity: "HIGH", issue: "Function() constructor - potential code injection" });
      }
      
      // DOM sinks
      if (/innerHTML|outerHTML|insertAdjacentHTML/.test(src)) {
        flags.push("DOM sink");
        risks.push({ severity: "MEDIUM", issue: "innerHTML/outerHTML - XSS risk if used with untrusted data" });
      }
      if (/document\.write/.test(src)) {
        flags.push("document.write");
        risks.push({ severity: "MEDIUM", issue: "document.write() - can lead to XSS" });
      }
      if (/dangerouslySetInnerHTML/.test(src)) {
        flags.push("dangerouslySetInnerHTML");
        risks.push({ severity: "HIGH", issue: "dangerouslySetInnerHTML - React XSS risk" });
      }
      
      // Storage access
      if (/localStorage|sessionStorage/.test(src)) {
        flags.push("storage access");
        if (/localStorage.*innerHTML|sessionStorage.*innerHTML/.test(src)) {
          risks.push({ severity: "HIGH", issue: "Storage to DOM sink - stored XSS potential" });
        }
      }
      if (/document\.cookie/.test(src)) {
        flags.push("cookie access");
      }
      
      // Network
      if (/fetch\s*\(|XMLHttpRequest|\.ajax\(/.test(src)) {
        flags.push("HTTP request");
      }
      if (/\/api\/|https?:\/\//.test(src)) {
        flags.push("endpoint usage");
      }
      
      // PostMessage
      if (/postMessage/.test(src)) {
        flags.push("postMessage");
        if (!/origin/.test(src)) {
          risks.push({ severity: "MEDIUM", issue: "postMessage without origin check" });
        }
      }
      
      // Window.open
      if (/window\.open/.test(src) && !/noopener/.test(src)) {
        flags.push("window.open");
        risks.push({ severity: "LOW", issue: "window.open without noopener - reverse tabnabbing risk" });
      }
      
      // Location/URL manipulation
      if (/location\.href|location\.replace|location\.assign/.test(src)) {
        flags.push("location manipulation");
        risks.push({ severity: "MEDIUM", issue: "URL manipulation - open redirect potential" });
      }

      return { flags, risks };
    };

    /**********************************************************
     * BUILD HTML
     **********************************************************/
    console.log("📊 Gathering data...");
    
    const siteInfo = getSiteInfo();
    const securityChecks = performSecurityChecks();
    const storage = getStorageData();
    const cookies = getCookies();
    const globalVars = getGlobalVars();
    
    console.log(`✓ Found ${cookies.length} cookies`);
    console.log(`✓ Found ${storage.localStorage.length} localStorage items`);
    console.log(`✓ Found ${storage.sessionStorage.length} sessionStorage items`);
    console.log(`✓ Found ${globalVars.length} global variables`);
    console.log(`✓ Detected ${siteInfo.frameworks.length} frameworks: ${siteInfo.frameworks.join(', ') || 'None'}`);
    console.log(`⚠️ Found ${securityChecks.length} security issues`);
    
    let nativeCount = 0;
    let customCount = 0;
    
    // Count native vs custom functions
    globals.forEach(g => {
      if (isNativeCode(g.src)) nativeCount++;
      else customCount++;
    });

    console.log(`✓ Analyzing ${customCount} custom functions (${nativeCount} native)`);

    let html = `
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>DefenceLogic – Client Exposure Inspector</title>
<style>
*{box-sizing:border-box}
body{background:#020617;color:#e5e7eb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:0;margin:0;line-height:1.6}
.container{max-width:1400px;margin:0 auto;padding:20px}
h1,h2,h3,h4{color:#38bdf8;margin-top:0}
h1{font-size:28px;border-bottom:2px solid #1e293b;padding-bottom:12px;margin-bottom:20px}
h2{font-size:22px;margin-bottom:12px}
h3{font-size:18px;margin-bottom:8px}
h4{font-size:16px;margin-bottom:6px}
.header{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);padding:24px;margin-bottom:24px;border-radius:12px;box-shadow:0 4px 6px rgba(0,0,0,0.3)}
.header h1{border:none;margin:0;color:#38bdf8}
.header .subtitle{color:#94a3b8;margin-top:8px;font-size:14px}
.section{border:1px solid #1e293b;border-radius:10px;padding:20px;margin-bottom:24px;background:#0f172a;box-shadow:0 2px 4px rgba(0,0,0,0.2)}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px}
.stat{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);padding:16px;border-radius:8px;text-align:center;border:1px solid #1e293b;transition:transform 0.2s}
.stat:hover{transform:translateY(-2px);border-color:#38bdf8}
.stat-value{font-size:36px;font-weight:700;color:#38bdf8;margin-bottom:4px}
.stat-label{font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px}
pre{background:#020617;border:1px solid #1e293b;padding:12px;white-space:pre-wrap;border-radius:6px;max-height:500px;overflow:auto;font-size:12px;font-family:'Consolas','Monaco',monospace;line-height:1.5;color:#e5e7eb}
.kw{color:#7dd3fc;font-weight:600}
.str{color:#a7f3d0}
.cmt{color:#64748b;font-style:italic}
.danger{color:#f87171;font-weight:700;background:#450a0a;padding:2px 4px;border-radius:3px}
.badge{display:inline-block;background:#7f1d1d;color:#fecaca;padding:3px 10px;border-radius:999px;font-size:11px;margin:2px 4px 2px 0;font-weight:500;white-space:nowrap}
.badge.info{background:#1e40af;color:#bfdbfe}
.badge.success{background:#065f46;color:#a7f3d0}
.badge.warning{background:#854d0e;color:#fef3c7}
.risk-high{background:#7f1d1d;color:#fecaca;padding:6px 10px;border-radius:6px;margin:6px 0;display:block;font-size:12px;border-left:3px solid #dc2626}
.risk-medium{background:#854d0e;color:#fef3c7;padding:6px 10px;border-radius:6px;margin:6px 0;display:block;font-size:12px;border-left:3px solid #ea580c}
.risk-low{background:#164e63;color:#cffafe;padding:6px 10px;border-radius:6px;margin:6px 0;display:block;font-size:12px;border-left:3px solid #0891b2}
.toggle-btn{background:#1e293b;color:#38bdf8;border:1px solid #38bdf8;padding:8px 16px;border-radius:6px;cursor:pointer;margin:8px 4px 8px 0;font-size:13px;font-weight:500;transition:all 0.2s;display:inline-block}
.toggle-btn:hover{background:#38bdf8;color:#020617;transform:translateY(-1px);box-shadow:0 2px 4px rgba(56,189,248,0.3)}
.toggle-btn:active{transform:translateY(0)}
.collapsible{display:none;margin-top:12px;animation:slideDown 0.3s ease}
.collapsible.active{display:block}
@keyframes slideDown{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
.native-indicator{color:#64748b;font-size:11px;margin-left:8px;font-weight:400}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #1e293b}
th{background:#1e293b;color:#38bdf8;font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:0.5px}
tr:hover{background:#1e293b}
.truncate{max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.item{margin:16px 0;padding:16px;background:#0f172a;border-left:3px solid #1e293b;border-radius:6px;transition:all 0.2s}
.item:hover{border-left-color:#38bdf8;box-shadow:0 2px 8px rgba(0,0,0,0.3)}
.item.has-risk{border-left-color:#f87171;background:#1a0f0f}
.info-grid{display:grid;grid-template-columns:200px 1fr;gap:8px 16px;font-size:13px}
.info-label{color:#94a3b8;font-weight:600}
.info-value{color:#e5e7eb;font-family:'Consolas','Monaco',monospace}
.security-check{margin:12px 0;padding:12px;border-radius:6px;background:#0f172a}
.alert-banner{background:#7f1d1d;color:#fecaca;padding:12px 16px;border-radius:8px;margin:16px 0;border-left:4px solid #dc2626}
.no-data{color:#64748b;font-style:italic;text-align:center;padding:20px}
code{background:#1e293b;color:#38bdf8;padding:2px 6px;border-radius:3px;font-size:12px;font-family:'Consolas','Monaco',monospace}
.export-btn{background:#059669;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;margin:8px 4px 8px 0;font-size:13px;font-weight:600;transition:all 0.2s}
.export-btn:hover{background:#047857;transform:translateY(-1px);box-shadow:0 2px 4px rgba(5,150,105,0.3)}
.top-bar{position:sticky;top:0;background:#020617;padding:12px 20px;border-bottom:2px solid #1e293b;z-index:1000;display:flex;justify-content:space-between;align-items:center}
.top-bar-title{font-size:16px;font-weight:600;color:#38bdf8}
.section h2{cursor:pointer;user-select:none;display:flex;justify-content:space-between;align-items:center;padding:8px 0;transition:color 0.2s}
.section h2:hover{color:#60a5fa}
.section h2::after{content:'▼';font-size:14px;transition:transform 0.3s}
.section h2.collapsed::after{transform:rotate(-90deg)}
.section-content{overflow:hidden;transition:max-height 0.3s ease;max-height:100000px}
.section-content.hidden{max-height:0!important}
</style>
</head>
<body>

<div class="top-bar">
  <div class="top-bar-title">🔍 DefenceLogic Inspector</div>
  <div>
    <button class="export-btn" onclick="downloadReport()" style="background:#059669;margin-right:8px">💾 Download Report</button>
    <button class="export-btn" onclick="window.print()">🖨️ Print Report</button>
  </div>
</div>

<div class="container">

<div class="header">
  <h1>🔍 DefenceLogic – Client Exposure Inspector</h1>
  <div class="subtitle">
    <strong>Target:</strong> ${escapeHtml(siteInfo.url)}<br>
    <strong>Generated:</strong> ${new Date().toLocaleString()}<br>
    <strong>Protocol:</strong> ${escapeHtml(siteInfo.protocol)} | 
    <strong>Frameworks:</strong> ${siteInfo.frameworks.length > 0 ? siteInfo.frameworks.map(f => `<span class="badge success">${escapeHtml(f)}</span>`).join('') : 'None detected'}
  </div>
</div>

<div class="summary">
  <div class="stat">
    <div class="stat-value">${customCount}</div>
    <div class="stat-label">Custom Functions</div>
  </div>
  <div class="stat">
    <div class="stat-value">${nativeCount}</div>
    <div class="stat-label">Native Functions</div>
  </div>
  <div class="stat">
    <div class="stat-value">${cookies.length}</div>
    <div class="stat-label">Cookies</div>
  </div>
  <div class="stat">
    <div class="stat-value">${storage.localStorage.length}</div>
    <div class="stat-label">localStorage</div>
  </div>
  <div class="stat">
    <div class="stat-value">${globalVars.length}</div>
    <div class="stat-label">Global Variables</div>
  </div>
  <div class="stat">
    <div class="stat-value">${securityChecks.filter(c => c.severity === 'HIGH').length}</div>
    <div class="stat-label">High Risks</div>
  </div>
</div>

<div class="section">
  <h2 class="collapsed" onclick="toggleSection(this)">🌐 Site Information</h2>
  <div class="section-content hidden">
  <div class="info-grid">
    <div class="info-label">URL:</div>
    <div class="info-value">${escapeHtml(siteInfo.url)}</div>
    
    <div class="info-label">Origin:</div>
    <div class="info-value">${escapeHtml(siteInfo.origin)}</div>
    
    <div class="info-label">Protocol:</div>
    <div class="info-value">${escapeHtml(siteInfo.protocol)} ${siteInfo.protocol === 'https:' ? '<span class="badge success">Secure</span>' : '<span class="badge">⚠️ Insecure</span>'}</div>
    
    <div class="info-label">Hostname:</div>
    <div class="info-value">${escapeHtml(siteInfo.hostname)}</div>
    
    <div class="info-label">Port:</div>
    <div class="info-value">${escapeHtml(siteInfo.port)}</div>
    
    <div class="info-label">Document Title:</div>
    <div class="info-value">${escapeHtml(siteInfo.documentTitle)}</div>
    
    <div class="info-label">Referrer:</div>
    <div class="info-value">${escapeHtml(siteInfo.referrer)}</div>
    
    <div class="info-label">Charset:</div>
    <div class="info-value">${escapeHtml(siteInfo.charset)}</div>
    
    <div class="info-label">User Agent:</div>
    <div class="info-value" style="max-width:600px;word-break:break-all">${escapeHtml(siteInfo.userAgent)}</div>
    
    <div class="info-label">Platform:</div>
    <div class="info-value">${escapeHtml(siteInfo.platform)}</div>
    
    <div class="info-label">Language:</div>
    <div class="info-value">${escapeHtml(siteInfo.language)}</div>
    
    <div class="info-label">Viewport:</div>
    <div class="info-value">${escapeHtml(siteInfo.viewport)}</div>
    
    <div class="info-label">Screen:</div>
    <div class="info-value">${escapeHtml(siteInfo.screenResolution)} (${siteInfo.colorDepth}-bit)</div>
    
    <div class="info-label">Cookies Enabled:</div>
    <div class="info-value">${siteInfo.cookiesEnabled ? '<span class="badge success">Yes</span>' : '<span class="badge">No</span>'}</div>
    
    <div class="info-label">Online:</div>
    <div class="info-value">${siteInfo.onLine ? '<span class="badge success">Yes</span>' : '<span class="badge">Offline</span>'}</div>
    
    <div class="info-label">Frames:</div>
    <div class="info-value">${siteInfo.frameCount}</div>
    
    <div class="info-label">CSP (Meta):</div>
    <div class="info-value" style="max-width:600px;word-break:break-all">${escapeHtml(siteInfo.csp)}</div>
  </div>
  
  <h3 style="margin-top:20px">🔧 Technology Detection</h3>
  <div style="margin-top:12px">
    ${siteInfo.frameworks.length > 0 ? 
      '<p><strong>Frameworks:</strong> ' + siteInfo.frameworks.map(f => `<span class="badge success">${escapeHtml(f)}</span>`).join('') + '</p>' : 
      '<p class="no-data">No JavaScript frameworks detected</p>'}
    
    ${siteInfo.tracking.length > 0 ? 
      '<p><strong>Analytics/Tracking:</strong> ' + siteInfo.tracking.map(t => `<span class="badge info">${escapeHtml(t)}</span>`).join('') + '</p>' : 
      '<p class="no-data">No tracking scripts detected</p>'}
    
    <p><strong>Web APIs:</strong>
      ${siteInfo.hasServiceWorker ? '<span class="badge success">Service Worker</span>' : ''}
      ${siteInfo.hasWebWorker ? '<span class="badge success">Web Worker</span>' : ''}
      ${siteInfo.hasWebSocket ? '<span class="badge success">WebSocket</span>' : ''}
      ${siteInfo.hasIndexedDB ? '<span class="badge success">IndexedDB</span>' : ''}
      ${siteInfo.hasGeolocation ? '<span class="badge warning">Geolocation</span>' : ''}
      ${siteInfo.hasNotifications ? '<span class="badge warning">Notifications</span>' : ''}
    </p>
  </div>
  </div>
</div>

<div class="section">
  <h2 class="collapsed" onclick="toggleSection(this)">🛡️ Security Analysis (${securityChecks.length} Issues Found)</h2>
  <div class="section-content hidden">
  ${securityChecks.length === 0 ? 
    '<p class="no-data">✓ No obvious security issues detected</p>' : 
    securityChecks.map(check => `
      <div class="security-check">
        <span class="risk-${check.severity.toLowerCase()}">
          <strong>[${check.severity}]</strong> ${escapeHtml(check.category)}: ${escapeHtml(check.issue)}
        </span>
        <div style="margin-top:8px;padding-left:12px;color:#94a3b8;font-size:12px">
          💡 <em>${escapeHtml(check.recommendation)}</em>
        </div>
      </div>
    `).join('')
  }
  </div>
</div>

<div class="section">
  <h2 class="collapsed" onclick="toggleSection(this)">🍪 Cookies (${cookies.length})</h2>
  <div class="section-content hidden">
  ${cookies.length === 0 ? '<p style="color:#64748b">No cookies found or cookie access blocked</p>' : `
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Value</th>
        <th>Length</th>
      </tr>
    </thead>
    <tbody>
      ${cookies.map(c => `
        <tr>
          <td><code>${escapeHtml(c.name)}</code></td>
          <td class="truncate">${escapeHtml(c.value)}</td>
          <td>${c.length}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>
  <p style="color:#94a3b8;font-size:12px;margin-top:8px">⚠️ Note: HttpOnly cookies are not accessible via JavaScript</p>
  `}
  </div>
</div>

<div class="section">
  <h2 class="collapsed" onclick="toggleSection(this)">💾 Local Storage (${storage.localStorage.length})</h2>
  <div class="section-content hidden">
  ${storage.localStorage.length === 0 ? '<p style="color:#64748b">No localStorage data found</p>' : `
  <table>
    <thead>
      <tr>
        <th>Key</th>
        <th>Value</th>
        <th>Size</th>
      </tr>
    </thead>
    <tbody>
      ${storage.localStorage.map(item => `
        <tr>
          <td><code>${escapeHtml(item.key)}</code></td>
          <td class="truncate"><pre style="margin:0;background:transparent;border:none;padding:0">${escapeHtml(item.value)}</pre></td>
          <td>${item.length} chars</td>
        </tr>
      `).join('')}
    </tbody>
  </table>
  `}
  </div>
</div>

<div class="section">
  <h2 class="collapsed" onclick="toggleSection(this)">🔄 Session Storage (${storage.sessionStorage.length})</h2>
  <div class="section-content hidden">
  ${storage.sessionStorage.length === 0 ? '<p style="color:#64748b">No sessionStorage data found</p>' : `
  <table>
    <thead>
      <tr>
        <th>Key</th>
        <th>Value</th>
        <th>Size</th>
      </tr>
    </thead>
    <tbody>
      ${storage.sessionStorage.map(item => `
        <tr>
          <td><code>${escapeHtml(item.key)}</code></td>
          <td class="truncate"><pre style="margin:0;background:transparent;border:none;padding:0">${escapeHtml(item.value)}</pre></td>
          <td>${item.length} chars</td>
        </tr>
      `).join('')}
    </tbody>
  </table>
  `}
  </div>
</div>

<div class="section">
  <h2 class="collapsed" onclick="toggleSection(this)">🌐 Global Variables (${globalVars.length})</h2>
  <div class="section-content hidden">
  ${globalVars.length === 0 ? '<p style="color:#64748b">No custom global variables found</p>' : `
  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Type</th>
        <th>Value/Preview</th>
      </tr>
    </thead>
    <tbody>
      ${globalVars.map(v => `
        <tr>
          <td><code>${escapeHtml(v.name)}</code></td>
          <td><span class="badge info">${escapeHtml(v.type)}</span></td>
          <td class="truncate"><pre style="margin:0;background:transparent;border:none;padding:0;font-size:11px">${escapeHtml(v.value)}</pre></td>
        </tr>
      `).join('')}
    </tbody>
  </table>
  `}
  </div>
</div>

<div class="section">
  <h2 onclick="toggleSection(this)">⚙️ Functions & Classes</h2>
  <div class="section-content">
  <p style="color:#94a3b8;margin-bottom:16px">Analysis of ${customCount} custom functions (${nativeCount} native)</p>
`;

    let functionIndex = 0;
    
    globals.forEach(g => {
      const isNative = isNativeCode(g.src);
      const analysis = analyzeSource(g.src);
      const hasRisks = analysis.risks.length > 0;
      
      if (!isNative) {
        // Custom code only - analyze for risks
        const classes = extractClassesAndMethods(g.src);

        if (classes.length) {
          classes.forEach(cls => {
            html += `<div class="item ${hasRisks ? 'has-risk' : ''}">`;
            html += `<h3>Class: ${escapeHtml(cls.className)}</h3>`;
            
            cls.methods.forEach(m => {
              const methodAnalysis = analyzeSource(m.source);
              const methodHasRisks = methodAnalysis.risks.length > 0;
              html += `
                <div style="margin:12px 0">
                  <h4 style="margin:4px 0"><b>Method:</b> ${escapeHtml(m.name)}</h4>
                  ${methodAnalysis.flags.map(f => `<span class="badge">${escapeHtml(f)}</span>`).join("")}
                  ${methodAnalysis.risks.map(r => 
                    `<span class="risk-${r.severity.toLowerCase()}">[${r.severity}] ${escapeHtml(r.issue)}</span>`
                  ).join("")}
                  <button class="toggle-btn" onclick="document.getElementById('method-${functionIndex}').classList.toggle('active')">
                    Toggle Code
                  </button>
                  <div id="method-${functionIndex}" class="collapsible">
                    <pre>${highlightJS(m.source)}</pre>
                  </div>
                </div>`;
              functionIndex++;
            });
            html += `</div>`;
          });
        } else {
          // Get global vars referenced by this function
          const referencedVars = [];
          globalVars.forEach(v => {
            // Check if this function references the global variable
            const varPattern = new RegExp('\\b' + v.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b');
            if (varPattern.test(g.src)) {
              referencedVars.push(v.name);
            }
          });

          html += `
            <div class="item ${hasRisks ? 'has-risk' : ''}">
              <h3>Function: ${escapeHtml(g.name)}</h3>
              ${analysis.flags.map(f => `<span class="badge">${escapeHtml(f)}</span>`).join("")}
              ${analysis.risks.map(r => 
                `<span class="risk-${r.severity.toLowerCase()}">[${r.severity}] ${escapeHtml(r.issue)}</span>`
              ).join("")}
              ${referencedVars.length > 0 ? `
                <div style="margin-top:8px;color:#94a3b8;font-size:12px">
                  🔗 References global vars: ${referencedVars.map(v => `<code style="background:#1e293b;padding:2px 6px;border-radius:3px">${escapeHtml(v)}</code>`).join(', ')}
                </div>
              ` : ''}
              <button class="toggle-btn" onclick="document.getElementById('func-${functionIndex}').classList.toggle('active')">
                Toggle Code
              </button>
              <div id="func-${functionIndex}" class="collapsible">
                <pre>${highlightJS(g.src)}</pre>
              </div>
            </div>
          `;
        }
        functionIndex++;
      }
    });

    html += `
  </div>
</div>

<p style="text-align:center;color:#64748b;margin-top:40px;font-size:12px">
  Generated by DefenceLogic Client Exposure Inspector | ${new Date().toISOString()}
</p>

</body>
</html>`;

    /**********************************************************
     * RENDER - Open in new window as primary method
     **********************************************************/
    console.log("📄 Generating HTML report...");
    
    // Add download script to HTML
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
    const filename = `defencelogic-inspector-${window.location.hostname}-${timestamp}.html`;
    
    html += `
<script>
function toggleSection(header) {
  const content = header.nextElementSibling;
  const isHidden = content.classList.contains('hidden');
  
  if (isHidden) {
    content.classList.remove('hidden');
    content.style.maxHeight = content.scrollHeight + 'px';
    header.classList.remove('collapsed');
  } else {
    content.classList.add('hidden');
    content.style.maxHeight = '0';
    header.classList.add('collapsed');
  }
}

function downloadReport() {
  const htmlContent = document.documentElement.outerHTML;
  const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = '${filename}';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  alert('Report downloaded as ${filename}');
}
</script>`;
    
    const renderReport = () => {
      // Method 1: Try window.open (MOST RELIABLE - works on all sites)
      try {
        const w = window.open("", "_blank", "width=1400,height=900,menubar=yes,toolbar=yes,location=yes");
        if (w && w.document) {
          w.document.write(html);
          w.document.close();
          console.log("%c✅ Report Opened in New Window!", "color:#10b981;font-size:14px;font-weight:bold");
          console.log("%c💡 Use the green 'Download Report' button at the top to save the HTML file", "color:#94a3b8");
          return true;
        }
      } catch (e) {
        console.warn("[DefenceLogic Inspector] window.open blocked:", e);
      }

      // Method 2: Try Blob URL in new window
      try {
        console.log("Trying Blob URL method...");
        const blob = new Blob([html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const w = window.open(url, "_blank", "width=1400,height=900");
        if (w) {
          console.log("%c✅ Report Opened via Blob URL!", "color:#10b981;font-size:14px;font-weight:bold");
          setTimeout(() => URL.revokeObjectURL(url), 30000);
          return true;
        }
      } catch (e) {
        console.error("[DefenceLogic Inspector] Blob URL failed:", e);
      }

      // Method 3: Try data URI (works even with strict popup blockers)
      try {
        console.log("Trying data URI method...");
        const dataUri = 'data:text/html;charset=utf-8,' + encodeURIComponent(html);
        const w = window.open(dataUri, "_blank");
        if (w) {
          console.log("%c✅ Report Opened via Data URI!", "color:#10b981;font-size:14px;font-weight:bold");
          return true;
        }
      } catch (e) {
        console.error("[DefenceLogic Inspector] Data URI failed:", e);
      }

      return false;
    };

    if (!renderReport()) {
      console.error("%c❌ Popup blocked or window.open failed", "color:#ef4444;font-size:14px;font-weight:bold");
      
      // Last resort: Show instructions to user
      const instructions = 
        "⚠️ POPUP BLOCKED!\n\n" +
        "Your browser blocked the report window.\n\n" +
        "SOLUTION:\n" +
        "1. Check for a popup blocker icon in your address bar\n" +
        "2. Click it and select 'Always allow popups from this site'\n" +
        "3. Run the script again\n\n" +
        "OR\n\n" +
        "Copy the report HTML from the console below and save it manually.";
      
      alert(instructions);
      console.log("%c📋 COPY THIS HTML TO A FILE:", "color:#38bdf8;font-size:16px;font-weight:bold");
      console.log(html);
      console.log("%c💡 Save it as 'inspector-report.html' and open in your browser", "color:#94a3b8");
    }

  } catch (e) {
    console.error("%c[DefenceLogic Inspector] Critical error:", "color:#ef4444;font-size:14px;font-weight:bold", e);
    alert(`❌ Inspector failed to run.\n\nError: ${e.message}\n\nCheck browser console for details.`);
  }
})();
