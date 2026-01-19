# DefenceLogic – Client Exposure Inspector

A **read-only, client-side inspection tool** for identifying exposed JavaScript functions, global variables, accessible cookies, storage usage, and common client-side risk patterns in web applications.

This tool is designed for **web application penetration testers**, security reviewers, and engineers performing **manual client-side analysis**.

---

## ⚠️ Important Notice

* This tool performs **no exploitation**
* It **does not bypass** browser security controls
* It executes entirely within the **browser context**
* All analysis is **heuristic and observational**
* Findings must be **manually validated**

It is intended to **assist human analysis**, not replace it.

---

## Features

### Inventory & Recon

* Enumerates **exposed global variables**
* Enumerates **accessible (non-HttpOnly) cookies**
* Enumerates **non-native global JavaScript functions**
* Extracts **client-side URLs / API endpoints**

### Function-Level Analysis

For each exposed function, the tool identifies:

* Referenced global variables
* DOM **sources** (e.g. `location`, `localStorage`, `document.cookie`)
* DOM **sinks** (e.g. `innerHTML`, `eval`, `document.write`)
* Backend endpoints used by the function
* Storage reads and writes

### Risk-Oriented Heuristics

The tool highlights **high-value indicators**, including:

* `eval()` or `Function()` used with dynamic input
* Storage → sink correlations (e.g. `localStorage` → `innerHTML`)
* Possible storage-backed XSS patterns
* Potential **reverse tabnabbing** (`window.open` without `noopener`)
* Weak `postMessage` handling (listener without obvious origin checks)

These are **signals**, not proof of vulnerability.

### Usability

* Syntax-highlighted JavaScript output
* Clear per-function metadata
* Summary counts to guide review
* Automatic **JSON export** for evidence or appendix use
* Works on **CSP / Trusted Types–protected sites** (Google, YouTube, etc.)

---

## Usage

### ✅ Recommended: DevTools Loader (Most Reliable)

Paste this into the browser console on the target site:

```js
fetch("https://<username>.github.io/defencelogic-client-inspector/defencelogic-client-exposure.js")
  .then(r => r.text())
  .then(code => (0,eval)(code));
```

Why this works:

* Executes via DevTools (no CSP bypass)
* Works on hardened sites
* No script injection required

---

### Bookmarklet (Convenience)

Create a bookmark and set the URL to:

```js
javascript:(()=>{fetch("https://<username>.github.io/defencelogic-client-inspector/defencelogic-client-exposure.js").then(r=>r.text()).then(code=>(0,eval)(code))})()
```

Note:

* Bookmarklets may be blocked on some sites
* DevTools loader is always preferred

---

## Output

When executed, the tool:

* Opens a **new tab or isolated context** containing the report
* Displays:

  * Summary statistics
  * Global variables
  * Accessible cookies
  * Observed URLs/endpoints
  * Detailed per-function analysis
* Automatically downloads:

  ```
  defencelogic_client_exposure.json
  ```

This JSON file is suitable for:

* Evidence retention
* Appendix inclusion
* Offline review

---

## Interpreting Results (Guidance)

* **“Granted storage”** messages are normal browser behaviour
  Storage access alone is **not a vulnerability**
* Focus review on:

  * User-controlled sources → dangerous sinks
  * Storage-backed DOM manipulation
  * `eval()` or dynamic code execution
  * Client-side navigation helpers (`window.open`)
* All flagged items require **manual validation**

---

## Reporting Guidance

Suggested wording when referencing this tool:

> “Client-side analysis was performed using browser-delivered JavaScript inspection techniques. The analysis was read-only and did not bypass application security controls.”

Avoid claiming exploitability unless independently proven.

---

## Limitations

* Heuristic-based (may miss obfuscated code)
* No dynamic taint tracking
* Does not inspect server-side behaviour
* Does not access HttpOnly cookies

This is intentional to keep the tool **safe, portable, and defensible**.

---

## Intended Audience

* Web application penetration testers
* Security consultants
* AppSec engineers
* Security-aware developers

---

## License / Usage

Internal security testing and authorised assessments only.

Do not use on systems you do not own or have explicit permission to test.

---

## Credits

Created for practical, repeatable **manual client-side analysis**.
Created by Richard Jones at Defencelogic.io
Inspired by real-world web application testing workflows.
