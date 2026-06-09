/* HardenCheck — client-side security-header & cookie-flag scanner.
 * A Copper Bay Labs product. Sibling to ExposureCheck / LeakCheck.
 *
 * WHAT THIS DOES
 *   Grades a site's HTTP response headers and Set-Cookie flags, producing a
 *   screenshot-worthy A–F report card, a per-header findings list ranked by
 *   severity, and copy-paste fixes for nginx / Apache / Vercel / Next.js.
 *
 *   Two input modes:
 *     1. URL mode  — fetch the target through a PUBLIC CORS-proxy chain
 *        (fallback chain, per-request timeouts) and read whatever response
 *        headers the proxy exposes. Degrades gracefully if proxies fail or
 *        strip headers — it NEVER hangs, and it tells the user honestly when
 *        a proxy hides headers rather than fabricating a verdict.
 *     2. PASTE mode (always works, no network) — paste a raw HTTP response
 *        header block (e.g. from `curl -I` or DevTools) and grade it locally.
 *
 * SAFETY / PRIVACY
 *   100% client-side. No backend, no API keys, no analytics on your input.
 *   Nothing is stored or transmitted anywhere except the proxy fetch of the
 *   target URL in URL mode (paste mode makes no network call at all).
 *
 * XSS GUARANTEE
 *   The tool reads ARBITRARY remote/pasted header text. Every piece of that
 *   content reaches the DOM only via textContent (the el() helper) — never
 *   innerHTML. The only innerHTML-free clears (textContent = "") are of
 *   containers that hold no user data. Pasted/remote text cannot inject
 *   markup or run script. Fix snippets are author-controlled constants.
 */
(function () {
  "use strict";

  /* ================================================================== *
   * Severity ordering / metadata (shared with the suite stylesheet).
   * "pass" is a non-issue (header present & well-configured) shown last.
   * ================================================================== */
  var SEVERITIES = ["critical", "high", "medium", "low", "pass"];
  var ISSUE_SEVERITIES = ["critical", "high", "medium", "low"];
  var SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", pass: "Pass" };
  var SEV_ABBR = { critical: "crit", high: "high", medium: "med", low: "low", pass: "pass" };
  // Points deducted from 100 per issue, by severity. Drives the letter grade.
  var SEV_WEIGHT = { critical: 25, high: 16, medium: 9, low: 4, pass: 0 };

  /* ================================================================== *
   * Header check catalogue. Each entry knows how to grade a single
   * response header and explain it in plain English. `grade(value, all)`
   * returns { severity, observed, summary, detail } where:
   *   - value:    the raw header value (string) or null if absent.
   *   - all:      a lowercased name -> value map of every parsed header.
   * `fixes` maps platform -> a ready-to-paste snippet for the recommended
   * configuration. These snippets are author-written constants (XSS-safe).
   * ================================================================== */
  var CHECKS = [
    {
      key: "content-security-policy",
      title: "Content-Security-Policy",
      shortName: "CSP",
      what: "Controls which scripts, styles, images and other resources the browser is allowed to load — the single strongest defence against cross-site scripting (XSS).",
      grade: function (value) {
        if (value == null) {
          return {
            severity: "high",
            observed: null,
            summary: "No Content-Security-Policy header.",
            detail: "Without a CSP, an injected <script> or a compromised third-party tag runs with full access to your page. A CSP is the most effective single control against XSS and data exfiltration. Start with a restrictive policy and loosen it only as needed."
          };
        }
        var v = value.toLowerCase();
        var notes = [];
        var sev = "low";
        if (/(^|[\s;])default-src[^;]*'unsafe-inline'/.test(v) || /(^|[\s;])script-src[^;]*'unsafe-inline'/.test(v)) {
          notes.push("allows 'unsafe-inline' scripts, which largely defeats XSS protection");
          sev = "medium";
        }
        if (/'unsafe-eval'/.test(v)) {
          notes.push("allows 'unsafe-eval', letting strings be executed as code");
          sev = "medium";
        }
        if (/(script-src|default-src)[^;]*\*(?![.\w])/.test(v)) {
          notes.push("uses a wildcard (*) source, which permits scripts from any origin");
          sev = "medium";
        }
        if (!/object-src/.test(v) && !/default-src[^;]*'none'/.test(v)) {
          notes.push("does not set object-src 'none' (legacy plugin vector)");
        }
        if (notes.length === 0) {
          return {
            severity: "pass",
            observed: value,
            summary: "Content-Security-Policy is present.",
            detail: "A CSP is set, which is the strongest baseline control against XSS. Keep tightening it over time (prefer nonces/hashes over 'unsafe-inline', and add object-src 'none' and base-uri 'self')."
          };
        }
        return {
          severity: sev,
          observed: value,
          summary: "Content-Security-Policy is present but weakened.",
          detail: "A CSP is set, but it " + notes.join("; ") + ". These weaken its protection against injected scripts. Move toward nonces or hashes instead of 'unsafe-inline' and remove wildcards."
        };
      },
      fixes: {
        nginx: "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\" always;",
        apache: "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\"",
        vercel: "{\n  \"headers\": [{\n    \"source\": \"/(.*)\",\n    \"headers\": [{\n      \"key\": \"Content-Security-Policy\",\n      \"value\": \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\"\n    }]\n  }]\n}",
        next: "// next.config.js\nconst csp = \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\";\nmodule.exports = {\n  async headers() {\n    return [{\n      source: '/:path*',\n      headers: [{ key: 'Content-Security-Policy', value: csp }],\n    }];\n  },\n};"
      }
    },
    {
      key: "strict-transport-security",
      title: "Strict-Transport-Security",
      shortName: "HSTS",
      what: "Tells browsers to only ever connect over HTTPS, preventing protocol-downgrade and SSL-stripping man-in-the-middle attacks after the first visit.",
      grade: function (value) {
        if (value == null) {
          return {
            severity: "high",
            observed: null,
            summary: "No Strict-Transport-Security header.",
            detail: "Without HSTS, a network attacker can downgrade a visitor's first request to plain HTTP and intercept it (SSL stripping). HSTS forces HTTPS for a set duration so the downgrade window closes after the first secure visit."
          };
        }
        var m = /max-age\s*=\s*(\d+)/i.exec(value);
        var maxAge = m ? parseInt(m[1], 10) : 0;
        if (!m || maxAge === 0) {
          return {
            severity: "medium",
            observed: value,
            summary: "HSTS is present but max-age is missing or zero.",
            detail: "Strict-Transport-Security is sent, but max-age is missing or set to 0, which disables enforcement. Set max-age to at least 15552000 (180 days) so browsers actually remember to use HTTPS."
          };
        }
        if (maxAge < 15552000) {
          return {
            severity: "low",
            observed: value,
            summary: "HSTS is present but the max-age is short.",
            detail: "HSTS is enforced, but max-age (" + maxAge + "s) is shorter than the recommended 15552000s (180 days). A longer duration leaves a smaller downgrade window. Consider adding includeSubDomains and, once stable, preload."
          };
        }
        return {
          severity: "pass",
          observed: value,
          summary: "Strict-Transport-Security is configured.",
          detail: "HSTS is enforced with a healthy max-age. For full coverage, ensure includeSubDomains is set and consider submitting to the HSTS preload list once you are confident every subdomain is HTTPS-only."
        };
      },
      fixes: {
        nginx: "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;",
        apache: "Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"",
        vercel: "{\n  \"headers\": [{\n    \"source\": \"/(.*)\",\n    \"headers\": [{\n      \"key\": \"Strict-Transport-Security\",\n      \"value\": \"max-age=63072000; includeSubDomains; preload\"\n    }]\n  }]\n}",
        next: "// next.config.js — inside headers()[].headers\n{ key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' }"
      }
    },
    {
      key: "x-frame-options",
      title: "X-Frame-Options",
      shortName: "XFO",
      what: "Stops your pages from being embedded in an <iframe> on another site, the core defence against clickjacking.",
      grade: function (value, all) {
        var csp = all["content-security-policy"] || "";
        var cspFrames = /frame-ancestors/i.test(csp);
        if (value == null) {
          if (cspFrames) {
            return {
              severity: "pass",
              observed: null,
              summary: "Clickjacking is covered by CSP frame-ancestors.",
              detail: "X-Frame-Options is absent, but your Content-Security-Policy sets frame-ancestors, which is the modern replacement and is honoured by current browsers. Adding X-Frame-Options: DENY as well covers a few older clients."
            };
          }
          return {
            severity: "medium",
            observed: null,
            summary: "No X-Frame-Options (or CSP frame-ancestors).",
            detail: "Nothing prevents your pages from being framed by another site, which enables clickjacking — an attacker overlays your UI inside a hidden frame and tricks users into clicking. Set X-Frame-Options: DENY (or SAMEORIGIN) and ideally CSP frame-ancestors."
          };
        }
        var v = value.trim().toLowerCase();
        if (v === "deny" || v === "sameorigin") {
          return {
            severity: "pass",
            observed: value,
            summary: "X-Frame-Options is set correctly.",
            detail: "Framing is restricted (" + value.trim() + "), which protects against clickjacking. For defence in depth, also set Content-Security-Policy frame-ancestors, the modern equivalent."
          };
        }
        return {
          severity: "low",
          observed: value,
          summary: "X-Frame-Options has an unusual value.",
          detail: "The value \"" + value.trim() + "\" is not a standard directive. Modern browsers only honour DENY or SAMEORIGIN (the old ALLOW-FROM is deprecated). Use DENY or SAMEORIGIN, and CSP frame-ancestors for per-origin control."
        };
      },
      fixes: {
        nginx: "add_header X-Frame-Options \"DENY\" always;",
        apache: "Header always set X-Frame-Options \"DENY\"",
        vercel: "{\n  \"headers\": [{\n    \"source\": \"/(.*)\",\n    \"headers\": [{ \"key\": \"X-Frame-Options\", \"value\": \"DENY\" }]\n  }]\n}",
        next: "// next.config.js — inside headers()[].headers\n{ key: 'X-Frame-Options', value: 'DENY' }"
      }
    },
    {
      key: "x-content-type-options",
      title: "X-Content-Type-Options",
      shortName: "XCTO",
      what: "Stops browsers from MIME-sniffing a response away from its declared Content-Type, which can turn an uploaded file into executable script.",
      grade: function (value) {
        if (value == null) {
          return {
            severity: "medium",
            observed: null,
            summary: "No X-Content-Type-Options header.",
            detail: "Without this header, browsers may guess (\"sniff\") a response's type and, for example, run a file you served as text/plain as if it were JavaScript. Set X-Content-Type-Options: nosniff to force the declared Content-Type to be respected."
          };
        }
        if (value.trim().toLowerCase() === "nosniff") {
          return {
            severity: "pass",
            observed: value,
            summary: "X-Content-Type-Options: nosniff is set.",
            detail: "MIME-sniffing is disabled, so browsers honour your declared Content-Type. This is the recommended configuration."
          };
        }
        return {
          severity: "low",
          observed: value,
          summary: "X-Content-Type-Options has an unexpected value.",
          detail: "The only valid value is nosniff. \"" + value.trim() + "\" will be ignored by browsers, leaving MIME-sniffing enabled. Set it to exactly nosniff."
        };
      },
      fixes: {
        nginx: "add_header X-Content-Type-Options \"nosniff\" always;",
        apache: "Header always set X-Content-Type-Options \"nosniff\"",
        vercel: "{\n  \"headers\": [{\n    \"source\": \"/(.*)\",\n    \"headers\": [{ \"key\": \"X-Content-Type-Options\", \"value\": \"nosniff\" }]\n  }]\n}",
        next: "// next.config.js — inside headers()[].headers\n{ key: 'X-Content-Type-Options', value: 'nosniff' }"
      }
    },
    {
      key: "referrer-policy",
      title: "Referrer-Policy",
      shortName: "Referrer",
      what: "Controls how much of the current URL is sent in the Referer header when users click away, limiting how much you leak to third parties.",
      grade: function (value) {
        if (value == null) {
          return {
            severity: "low",
            observed: null,
            summary: "No Referrer-Policy header.",
            detail: "Browsers fall back to a default that can send the full URL (including path and query string) to other sites your users navigate to, leaking session tokens or IDs that live in URLs. Set a privacy-preserving policy like strict-origin-when-cross-origin or no-referrer."
          };
        }
        var v = value.trim().toLowerCase();
        var weak = ["unsafe-url", "no-referrer-when-downgrade", ""];
        if (weak.indexOf(v) !== -1) {
          return {
            severity: "low",
            observed: value,
            summary: "Referrer-Policy is weak.",
            detail: "The value \"" + value.trim() + "\" can still leak full URLs across origins. Prefer strict-origin-when-cross-origin (a good default) or no-referrer for maximum privacy."
          };
        }
        return {
          severity: "pass",
          observed: value,
          summary: "Referrer-Policy is set.",
          detail: "A privacy-preserving Referrer-Policy (" + value.trim() + ") is in place, limiting how much URL information leaks to other sites."
        };
      },
      fixes: {
        nginx: "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
        apache: "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
        vercel: "{\n  \"headers\": [{\n    \"source\": \"/(.*)\",\n    \"headers\": [{ \"key\": \"Referrer-Policy\", \"value\": \"strict-origin-when-cross-origin\" }]\n  }]\n}",
        next: "// next.config.js — inside headers()[].headers\n{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }"
      }
    },
    {
      key: "permissions-policy",
      title: "Permissions-Policy",
      shortName: "Permissions",
      what: "Switches off powerful browser features (camera, microphone, geolocation, etc.) that your site does not use, shrinking the attack surface if it is ever compromised.",
      grade: function (value) {
        if (value == null) {
          return {
            severity: "low",
            observed: null,
            summary: "No Permissions-Policy header.",
            detail: "Without this header, an injected script or a third-party frame could request access to the camera, microphone, geolocation, and other powerful APIs. Explicitly disable the features you don't use so a compromise can't reach them."
          };
        }
        return {
          severity: "pass",
          observed: value,
          summary: "Permissions-Policy is set.",
          detail: "A Permissions-Policy is in place, limiting which powerful browser features can be used. Review it to confirm it disables everything your site does not actually need (camera, microphone, geolocation, etc.)."
        };
      },
      fixes: {
        nginx: "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=(), interest-cohort=()\" always;",
        apache: "Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=(), interest-cohort=()\"",
        vercel: "{\n  \"headers\": [{\n    \"source\": \"/(.*)\",\n    \"headers\": [{\n      \"key\": \"Permissions-Policy\",\n      \"value\": \"camera=(), microphone=(), geolocation=(), interest-cohort=()\"\n    }]\n  }]\n}",
        next: "// next.config.js — inside headers()[].headers\n{ key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()' }"
      }
    },
    {
      key: "cross-origin-opener-policy",
      title: "Cross-Origin-Opener-Policy",
      shortName: "COOP",
      what: "Isolates your page from windows it opens (or that open it), defending against cross-origin attacks like Spectre and tab-nabbing.",
      grade: function (value) {
        if (value == null) {
          return {
            severity: "low",
            observed: null,
            summary: "No Cross-Origin-Opener-Policy header.",
            detail: "COOP isolates your browsing context from cross-origin windows, blocking a class of side-channel and tab-napping attacks and enabling cross-origin isolation. Set Cross-Origin-Opener-Policy: same-origin."
          };
        }
        var v = value.trim().toLowerCase();
        if (v === "same-origin" || v === "same-origin-allow-popups") {
          return {
            severity: "pass",
            observed: value,
            summary: "Cross-Origin-Opener-Policy is set.",
            detail: "COOP (" + value.trim() + ") isolates your page from cross-origin windows. This is a good configuration."
          };
        }
        return {
          severity: "low",
          observed: value,
          summary: "Cross-Origin-Opener-Policy is permissive.",
          detail: "The value \"" + value.trim() + "\" (e.g. unsafe-none) does not isolate your page. Use same-origin (or same-origin-allow-popups if you rely on OAuth pop-ups)."
        };
      },
      fixes: {
        nginx: "add_header Cross-Origin-Opener-Policy \"same-origin\" always;",
        apache: "Header always set Cross-Origin-Opener-Policy \"same-origin\"",
        vercel: "{\n  \"headers\": [{\n    \"source\": \"/(.*)\",\n    \"headers\": [{ \"key\": \"Cross-Origin-Opener-Policy\", \"value\": \"same-origin\" }]\n  }]\n}",
        next: "// next.config.js — inside headers()[].headers\n{ key: 'Cross-Origin-Opener-Policy', value: 'same-origin' }"
      }
    },
    {
      key: "cross-origin-resource-policy",
      title: "Cross-Origin-Resource-Policy",
      shortName: "CORP",
      what: "Declares who is allowed to embed your resources, helping block cross-origin leaks of your content.",
      grade: function (value) {
        if (value == null) {
          return {
            severity: "low",
            observed: null,
            summary: "No Cross-Origin-Resource-Policy header.",
            detail: "CORP lets you say which origins may load your resources, mitigating cross-origin information leaks (e.g. Spectre-style side channels). Set Cross-Origin-Resource-Policy: same-origin for private resources, or same-site / cross-origin for assets meant to be shared."
          };
        }
        var v = value.trim().toLowerCase();
        if (v === "same-origin" || v === "same-site" || v === "cross-origin") {
          return {
            severity: "pass",
            observed: value,
            summary: "Cross-Origin-Resource-Policy is set.",
            detail: "CORP (" + value.trim() + ") is configured. Use same-origin for sensitive resources; cross-origin is appropriate only for assets you intend other sites to embed."
          };
        }
        return {
          severity: "low",
          observed: value,
          summary: "Cross-Origin-Resource-Policy has an unexpected value.",
          detail: "Valid values are same-origin, same-site, or cross-origin. \"" + value.trim() + "\" will be ignored. Pick the most restrictive value your site can use."
        };
      },
      fixes: {
        nginx: "add_header Cross-Origin-Resource-Policy \"same-origin\" always;",
        apache: "Header always set Cross-Origin-Resource-Policy \"same-origin\"",
        vercel: "{\n  \"headers\": [{\n    \"source\": \"/(.*)\",\n    \"headers\": [{ \"key\": \"Cross-Origin-Resource-Policy\", \"value\": \"same-origin\" }]\n  }]\n}",
        next: "// next.config.js — inside headers()[].headers\n{ key: 'Cross-Origin-Resource-Policy', value: 'same-origin' }"
      }
    }
  ];

  // Headers that leak server/stack details — worth flagging as a low-risk hygiene note.
  var DISCLOSURE_HEADERS = [
    { key: "server", label: "Server", note: "reveals your web-server software/version, helping attackers target known vulnerabilities" },
    { key: "x-powered-by", label: "X-Powered-By", note: "advertises your framework/runtime (e.g. Express, PHP), narrowing an attacker's search for exploits" },
    { key: "x-aspnet-version", label: "X-AspNet-Version", note: "exposes your ASP.NET version" },
    { key: "x-aspnetmvc-version", label: "X-AspNetMvc-Version", note: "exposes your ASP.NET MVC version" }
  ];

  // Platform display names for fix tabs.
  var PLATFORMS = [
    { id: "nginx", label: "nginx" },
    { id: "apache", label: "Apache" },
    { id: "vercel", label: "Vercel" },
    { id: "next", label: "Next.js" }
  ];

  /* ================================================================== *
   * Header parsing. Accepts a raw HTTP response block (with or without
   * the status line), or a Headers object's entries. Folds duplicate
   * names. Set-Cookie is kept as a list because it legitimately repeats.
   * Returns { map: {lowerName: value}, cookies: [rawCookieLine], status }.
   * ================================================================== */
  function parseHeaderBlock(text) {
    var map = Object.create(null);
    var cookies = [];
    var status = null;
    var lines = String(text).replace(/\r\n/g, "\n").split("\n");
    var lastName = null;
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (line.trim() === "") { lastName = null; continue; }
      // Status line: "HTTP/1.1 200 OK" or "HTTP/2 200".
      if (/^HTTP\/[\d.]+\s+\d{3}/i.test(line) && status == null) {
        var sm = /\s(\d{3})/.exec(line);
        if (sm) status = parseInt(sm[1], 10);
        continue;
      }
      // Folded continuation (line starts with whitespace) appends to previous.
      if (/^[ \t]/.test(line) && lastName) {
        if (lastName === "set-cookie") {
          if (cookies.length) cookies[cookies.length - 1] += " " + line.trim();
        } else {
          map[lastName] += " " + line.trim();
        }
        continue;
      }
      var idx = line.indexOf(":");
      if (idx === -1) continue;
      var name = line.slice(0, idx).trim().toLowerCase();
      var value = line.slice(idx + 1).trim();
      if (!name) continue;
      lastName = name;
      if (name === "set-cookie") {
        cookies.push(value);
      } else if (name in map) {
        map[name] += ", " + value; // fold duplicate (non-cookie) headers
      } else {
        map[name] = value;
      }
    }
    return { map: map, cookies: cookies, status: status };
  }

  /* ================================================================== *
   * Cookie flag analysis. Each Set-Cookie line is graded for the three
   * flags that matter: Secure, HttpOnly, SameSite. We never store/echo
   * the cookie VALUE — only its name and flags reach the DOM.
   * ================================================================== */
  function cookieName(rawCookie) {
    var eq = rawCookie.indexOf("=");
    var name = eq === -1 ? rawCookie.split(";")[0].trim() : rawCookie.slice(0, eq).trim();
    return name || "(unnamed cookie)";
  }

  function analyzeCookie(rawCookie) {
    var name = cookieName(rawCookie);
    var attrs = rawCookie.split(";").slice(1).map(function (a) { return a.trim().toLowerCase(); });
    var hasSecure = attrs.indexOf("secure") !== -1;
    var hasHttpOnly = attrs.indexOf("httponly") !== -1;
    var sameSite = null;
    for (var i = 0; i < attrs.length; i++) {
      var m = /^samesite=(.+)$/.exec(attrs[i]);
      if (m) { sameSite = m[1]; break; }
    }
    var missing = [];
    if (!hasSecure) missing.push("Secure");
    if (!hasHttpOnly) missing.push("HttpOnly");
    if (!sameSite) missing.push("SameSite");

    var severity, summary, detail;
    if (missing.length === 0) {
      severity = "pass";
      summary = "Cookie \"" + name + "\" sets Secure, HttpOnly and SameSite.";
      detail = "This cookie is well-protected: Secure keeps it off plain HTTP, HttpOnly hides it from JavaScript (so XSS can't steal it), and SameSite=" + sameSite + " limits cross-site sending.";
    } else {
      // A cookie missing BOTH Secure and HttpOnly is wholly exposed: it can be
      // intercepted on plain HTTP *and* read by any injected script — the worst
      // case for a session/auth cookie, so it's genuinely critical.
      if (!hasSecure && !hasHttpOnly) severity = "critical";
      // Missing just one of HttpOnly/Secure is still high; only SameSite is medium.
      else if (!hasSecure || !hasHttpOnly) severity = "high";
      else severity = "medium";
      var parts = [];
      if (!hasSecure) parts.push("Secure (can be sent over unencrypted HTTP and intercepted)");
      if (!hasHttpOnly) parts.push("HttpOnly (readable by JavaScript, so an XSS bug can steal it)");
      if (!sameSite) parts.push("SameSite (sent on cross-site requests, enabling CSRF)");
      summary = "Cookie \"" + name + "\" is missing " + missing.join(", ") + ".";
      detail = "This cookie does not set " + joinList(parts) + ". For session or auth cookies, set all three: Secure; HttpOnly; SameSite=Lax (or Strict).";
    }
    return {
      type: "cookie",
      name: name,
      // `title` is shown as the card heading via textContent (XSS-safe even
      // though `name` is user/remote-derived).
      title: "Cookie: " + name,
      severity: severity,
      observed: name + ": " + (missing.length ? "missing " + missing.join(", ") : "Secure; HttpOnly; SameSite=" + sameSite),
      summary: summary,
      detail: detail,
      // Cookies have no platform fix snippet (fixes are framework-specific);
      // the detail text carries the remediation.
      fixes: null
    };
  }

  function joinList(arr) {
    if (arr.length === 1) return arr[0];
    if (arr.length === 2) return arr[0] + " and " + arr[1];
    return arr.slice(0, -1).join(", ") + ", and " + arr[arr.length - 1];
  }

  /* ================================================================== *
   * Grade the full set of headers + cookies. Returns:
   *   { findings: [...], cookieFindings: [...], grade, score, counts,
   *     headersAvailable }
   * findings include both issues and passes (passes for the report card).
   * ================================================================== */
  function gradeAll(parsed) {
    var map = parsed.map;
    var findings = [];
    for (var i = 0; i < CHECKS.length; i++) {
      var chk = CHECKS[i];
      var raw = (chk.key in map) ? map[chk.key] : null;
      var result = chk.grade(raw, map);
      findings.push({
        type: "header",
        key: chk.key,
        title: chk.title,
        shortName: chk.shortName,
        what: chk.what,
        fixes: chk.fixes,
        severity: result.severity,
        observed: result.observed,
        summary: result.summary,
        detail: result.detail
      });
    }

    // Escalation: if BOTH the Content-Security-Policy and Strict-Transport-Security
    // headers are entirely absent, the two strongest controls (against XSS and
    // against HTTPS downgrade) are missing at once. Treat that combination as
    // critical — a site shipping with neither is exposed on both fronts.
    var cspMissing = !("content-security-policy" in map);
    var hstsMissing = !("strict-transport-security" in map);
    if (cspMissing && hstsMissing) {
      for (var e = 0; e < findings.length; e++) {
        if (findings[e].key === "content-security-policy" || findings[e].key === "strict-transport-security") {
          findings[e].severity = "critical";
        }
      }
    }

    // Information-disclosure headers (low severity hygiene).
    for (var d = 0; d < DISCLOSURE_HEADERS.length; d++) {
      var dh = DISCLOSURE_HEADERS[d];
      if (dh.key in map && map[dh.key]) {
        findings.push({
          type: "disclosure",
          key: dh.key,
          title: dh.label + " header",
          shortName: dh.label,
          what: "Reveals server/stack details.",
          fixes: null,
          severity: "low",
          observed: dh.label + ": " + map[dh.key],
          summary: dh.label + " header exposes implementation details.",
          detail: "The " + dh.label + " header " + dh.note + ". It provides no benefit to visitors. Remove or blank it at your web server / framework (e.g. nginx server_tokens off; or app.disable('x-powered-by') in Express)."
        });
      }
    }

    // Cookies.
    var cookieFindings = [];
    for (var c = 0; c < parsed.cookies.length; c++) {
      cookieFindings.push(analyzeCookie(parsed.cookies[c]));
    }

    // Score: start at 100, subtract weighted issues.
    var all = findings.concat(cookieFindings);
    var score = 100;
    var counts = { critical: 0, high: 0, medium: 0, low: 0, pass: 0 };
    for (var k = 0; k < all.length; k++) {
      var sev = all[k].severity;
      counts[sev] = (counts[sev] || 0) + 1;
      score -= SEV_WEIGHT[sev] || 0;
    }
    if (score < 0) score = 0;

    return {
      findings: findings,
      cookieFindings: cookieFindings,
      score: score,
      grade: letterGrade(score),
      counts: counts
    };
  }

  function letterGrade(score) {
    if (score >= 90) return "A";
    if (score >= 80) return "B";
    if (score >= 65) return "C";
    if (score >= 45) return "D";
    return "F";
  }

  function gradeVerdict(grade, counts) {
    var issues = counts.critical + counts.high + counts.medium + counts.low;
    switch (grade) {
      case "A": return "Strong header hygiene.";
      case "B": return "Good, with a few gaps to close.";
      case "C": return "Some important headers are missing.";
      case "D": return "Several key protections are missing.";
      default:
        if (!issues) return "No headers could be graded.";
        return counts.critical ? "Critical protections are missing." : "Key protections are missing.";
    }
  }

  /* ================================================================== *
   * Networking — CORS-proxy fallback chain with per-request timeouts.
   * Public proxies frequently STRIP response headers, so we try a chain
   * and detect whether any security-relevant headers actually came back.
   * fetchHeadersViaProxy resolves { ok, status, headers, source } or
   * rejects on total failure. It NEVER hangs.
   * ================================================================== */
  // A proxy entry may expose EITHER:
  //   parse(body)        — for JSON-envelope proxies that embed the target's
  //                        response headers in their body (read via resp.text()).
  //   fromResponse(resp) — for raw-passthrough proxies that forward the target's
  //                        response (and its headers) directly; we read them off
  //                        the Response object. Returns { headerText, httpStatus }
  //                        or null if no usable security headers came through.
  // The chain tries each in order; fromResponse takes priority when present.
  var PROXIES = [
    // allorigins "get" returns JSON including a status.headers object — best
    // chance of preserving the target's response headers.
    {
      build: function (u) { return "https://api.allorigins.win/get?url=" + encodeURIComponent(u); },
      parse: function (body) {
        try {
          var json = JSON.parse(body);
          if (json && json.status && json.status.headers) {
            var lines = [];
            var h = json.status.headers;
            for (var name in h) {
              if (Object.prototype.hasOwnProperty.call(h, name)) {
                lines.push(name + ": " + h[name]);
              }
            }
            return { headerText: lines.join("\n"), httpStatus: json.status.http_code || null };
          }
        } catch (e) {}
        return null;
      }
    },
    // corsproxy.io forwards the upstream response with CORS enabled, so the
    // target's response headers arrive on the Response object itself. A second,
    // independent header-preserving path: if allorigins is down or rate-limited
    // this can still produce a real grade. (Some headers the Fetch spec marks
    // "forbidden" won't be exposed, but CSP/HSTS/XFO/etc. generally are.)
    {
      build: function (u) { return "https://corsproxy.io/?url=" + encodeURIComponent(u); },
      fromResponse: function (resp) { return headerTextFromResponse(resp); }
    }
  ];

  // Read a header text block off a Response object. Returns { headerText,
  // httpStatus } or null when no headers are exposed (so the chain can fall
  // through to the next proxy instead of grading an empty response).
  function headerTextFromResponse(resp) {
    var lines = [];
    if (resp.headers && typeof resp.headers.forEach === "function") {
      resp.headers.forEach(function (val, name) { lines.push(name + ": " + val); });
    }
    if (!lines.length) return null;
    return { headerText: lines.join("\n"), httpStatus: resp.status || null };
  }
  var REQUEST_TIMEOUT_MS = 11000;

  function timeoutFetch(url, ms) {
    return new Promise(function (resolve, reject) {
      var settled = false;
      var ctrl = (typeof AbortController !== "undefined") ? new AbortController() : null;
      var timer = setTimeout(function () {
        if (settled) return;
        settled = true;
        if (ctrl) { try { ctrl.abort(); } catch (e) {} }
        reject(new Error("timeout"));
      }, ms);
      var opts = { method: "GET", redirect: "follow", credentials: "omit" };
      if (ctrl) opts.signal = ctrl.signal;
      fetch(url, opts).then(function (resp) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(resp);
      }).catch(function (err) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  // Try the JSON proxy first (it can carry headers), then fall back to a
  // direct same-origin fetch attempt (works only if the target sends CORS,
  // but when it does we get real, complete headers). Resolves a header text
  // block plus a flag for whether we got a usable response at all.
  function fetchHeaders(targetUrl) {
    return new Promise(function (resolve, reject) {
      var idx = 0;
      function tryProxy() {
        if (idx >= PROXIES.length) {
          // Last resort: a direct fetch. Most sites won't allow it, but if
          // they do, response.headers are real and complete.
          directFetch(targetUrl).then(resolve, function () {
            reject(new Error("all-proxies-failed"));
          });
          return;
        }
        var proxy = PROXIES[idx++];
        timeoutFetch(proxy.build(targetUrl), REQUEST_TIMEOUT_MS).then(function (resp) {
          if (resp.status === 429 || resp.status === 403 || resp.status >= 500) {
            tryProxy();
            return;
          }
          function settle(parsedProxy) {
            if (parsedProxy && parsedProxy.headerText) {
              resolve({
                headerText: parsedProxy.headerText,
                httpStatus: parsedProxy.httpStatus,
                via: "proxy"
              });
            } else {
              tryProxy();
            }
          }
          // Raw-passthrough proxies expose the target headers on the Response;
          // JSON-envelope proxies embed them in the body.
          if (typeof proxy.fromResponse === "function") {
            try { settle(proxy.fromResponse(resp)); }
            catch (e) { tryProxy(); }
          } else {
            resp.text().then(function (body) {
              settle(proxy.parse(body));
            }, function () { tryProxy(); });
          }
        }).catch(function () { tryProxy(); });
      }
      tryProxy();
    });
  }

  function directFetch(targetUrl) {
    return timeoutFetch(targetUrl, REQUEST_TIMEOUT_MS).then(function (resp) {
      var got = headerTextFromResponse(resp);
      if (!got) throw new Error("no-headers");
      return { headerText: got.headerText, httpStatus: got.httpStatus, via: "direct" };
    });
  }

  /* ================================================================== *
   * URL helpers.
   * ================================================================== */
  function normalizeUrl(raw) {
    var s = String(raw || "").trim();
    if (!s) return null;
    if (!/^https?:\/\//i.test(s)) s = "https://" + s;
    try {
      var u = new URL(s);
      if (u.protocol !== "http:" && u.protocol !== "https:") return null;
      return u;
    } catch (e) {
      return null;
    }
  }

  /* ================================================================== *
   * DOM helpers. All user/remote-derived text uses textContent.
   * ================================================================== */
  // Monotonic id source for wiring ARIA relationships (tab <-> tabpanel).
  var UID = 0;
  function nextId(prefix) { UID += 1; return (prefix || "hc") + "-" + UID; }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text; // safe: escaped by the DOM
    return node;
  }
  function svgIcon(paths) {
    // Build a small inline icon from author-controlled path data (no user data).
    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    for (var i = 0; i < paths.length; i++) {
      var p = document.createElementNS(ns, "path");
      p.setAttribute("d", paths[i]);
      svg.appendChild(p);
    }
    return svg;
  }
  function announce(liveRegion, msg) {
    if (liveRegion) liveRegion.textContent = msg;
  }

  function renderProgress(results, label) {
    results.textContent = "";
    var wrap = el("div", "summary-bar");
    var spinner = el("span", "scan-spinner");
    spinner.setAttribute("aria-hidden", "true");
    wrap.appendChild(spinner);
    wrap.appendChild(el("p", "summary-headline", label || "Grading headers…"));
    results.appendChild(wrap);
    results.hidden = false;
  }

  /* ================================================================== *
   * Render the full report: the grade card (hero), the findings, fixes.
   * ================================================================== */
  function render(graded, meta, results, liveRegion, ctx) {
    results.textContent = "";

    var head = el("div", "results-head");
    head.appendChild(el("h2", null, "Report card"));
    if (meta && meta.target) head.appendChild(el("span", "meta", meta.target));
    results.appendChild(head);

    results.appendChild(buildReportCard(graded, meta, ctx));

    // Order issues by severity, then group; passes go into a collapsible-style
    // "Looking good" group at the end.
    var allFindings = graded.findings.concat(graded.cookieFindings);
    var issues = allFindings.filter(function (f) { return f.severity !== "pass"; });
    var passes = allFindings.filter(function (f) { return f.severity === "pass"; });

    issues.sort(function (a, b) {
      return ISSUE_SEVERITIES.indexOf(a.severity) - ISSUE_SEVERITIES.indexOf(b.severity);
    });

    if (issues.length) {
      for (var g = 0; g < ISSUE_SEVERITIES.length; g++) {
        var sev = ISSUE_SEVERITIES[g];
        var group = issues.filter(function (f) { return f.severity === sev; });
        if (!group.length) continue;
        var wrap = el("div", "finding-group");
        wrap.appendChild(el("h3", "group-head", SEV_LABEL[sev] + " (" + group.length + ")"));
        for (var c = 0; c < group.length; c++) wrap.appendChild(buildCard(group[c], ctx));
        results.appendChild(wrap);
      }
    }

    if (passes.length) {
      var pwrap = el("div", "finding-group");
      pwrap.appendChild(el("h3", "group-head", "Looking good (" + passes.length + ")"));
      for (var p = 0; p < passes.length; p++) pwrap.appendChild(buildCard(passes[p], ctx));
      results.appendChild(pwrap);
    }

    var disc = el("p", "results-disclaimer");
    disc.textContent = "HardenCheck grades response headers and cookie flags only — it is a quick hardening check, not a full security audit or guarantee. Header values are read as provided" + (meta && meta.via === "proxy" ? " through a public CORS proxy" : "") + ".";
    results.appendChild(disc);

    results.hidden = false;
    var issueCount = issues.length;
    announce(liveRegion, "Grade " + graded.grade + ". " + issueCount + (issueCount === 1 ? " issue" : " issues") + " found.");
  }

  function buildReportCard(graded, meta, ctx) {
    var card = el("div", "report-card grade-" + graded.grade);

    var panel = el("div", "grade-panel");
    var ring = el("div", "grade-ring");
    ring.appendChild(el("span", "grade-letter", graded.grade));
    panel.appendChild(ring);
    panel.appendChild(el("span", "grade-score", graded.score + " / 100"));
    card.appendChild(panel);

    var detail = el("div", "report-detail");
    if (meta && meta.target) {
      var tgt = el("span", "report-target", meta.target);
      detail.appendChild(tgt);
    }
    detail.appendChild(el("p", "report-verdict", gradeVerdict(graded.grade, graded.counts)));

    var counts = graded.counts;
    var sub = countSubline(counts);
    detail.appendChild(el("p", "report-sub", sub));

    var pills = el("div", "report-counts");
    var order = ["critical", "high", "medium", "low", "pass"];
    for (var i = 0; i < order.length; i++) {
      var sev = order[i];
      if (!counts[sev]) continue;
      var pill = el("span", "sev-count " + SEV_ABBR[sev]);
      pill.appendChild(el("span", "dot"));
      pill.appendChild(el("span", "n", String(counts[sev])));
      pill.appendChild(el("span", null, sev === "pass" ? "Pass" : SEV_LABEL[sev]));
      pills.appendChild(pill);
    }
    detail.appendChild(pills);

    var actions = el("div", "report-actions");
    var copyBtn = el("button", "copy-button");
    copyBtn.type = "button";
    copyBtn.appendChild(svgIcon(["M8 4v12a2 2 0 0 0 2 2h8", "M16 4H10a2 2 0 0 0-2 2v0", "M20 8h-8a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2z"]));
    copyBtn.appendChild(el("span", null, "Copy report"));
    copyBtn.addEventListener("click", function () {
      copyText(buildReport(graded, meta), copyBtn, "Copy report");
    });
    actions.appendChild(copyBtn);
    detail.appendChild(actions);

    card.appendChild(detail);
    return card;
  }

  function countSubline(counts) {
    var issues = counts.critical + counts.high + counts.medium + counts.low;
    var passed = counts.pass;
    if (issues === 0) {
      return "Every header we check is present and well-configured. Keep it that way as your site grows.";
    }
    return issues + (issues === 1 ? " issue" : " issues") + " to fix" +
      (passed ? ", " + passed + " check" + (passed === 1 ? "" : "s") + " already passing" : "") +
      ". The fixes below are copy-paste ready for your platform.";
  }

  /* Build a single finding card. */
  function buildCard(finding, ctx) {
    var card = el("article", "finding sev-" + finding.severity);

    var head = el("div", "finding-head");
    var badge = el("span", "sev-badge sev-" + finding.severity);
    badge.appendChild(el("span", "dot"));
    badge.appendChild(el("span", null, SEV_LABEL[finding.severity]));
    head.appendChild(badge);
    head.appendChild(el("span", "finding-title", finding.title));
    card.appendChild(head);

    // What it is (one line) — author-controlled, but textContent regardless.
    if (finding.what) {
      card.appendChild(el("p", "finding-desc", finding.what));
    }

    // Observed value (or "missing") — this is the user/remote-derived part.
    var ev = el("code", "evidence" + (finding.observed == null ? " missing" : ""));
    ev.appendChild(el("span", "label", "Observed"));
    if (finding.observed == null) {
      ev.appendChild(document.createTextNode("Header not present in the response."));
    } else {
      ev.appendChild(document.createTextNode(finding.observed)); // textContent-safe
    }
    card.appendChild(ev);

    // The plain-English summary + detail.
    card.appendChild(el("p", "finding-desc", finding.detail));

    // The fix block (only for header checks that aren't already passing, and
    // that carry fix snippets).
    if (finding.fixes && finding.severity !== "pass") {
      card.appendChild(buildFix(finding, ctx));
    } else if (finding.fixes && finding.severity === "pass") {
      // Passing header: still offer the recommended snippet, collapsed-feel.
      card.appendChild(buildFix(finding, ctx, true));
    }

    return card;
  }

  /* Build a fix block with platform tabs + copyable snippets. */
  function buildFix(finding, ctx, passing) {
    var fix = el("div", "fix");
    var label = el("span", "fix-label");
    label.appendChild(svgIcon(["M9 12l2 2 4-4", "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z"]));
    label.appendChild(el("span", null, passing ? "Recommended configuration" : "How to fix"));
    fix.appendChild(label);

    var tabs = el("div", "fix-tabs");
    tabs.setAttribute("role", "tablist");
    tabs.setAttribute("aria-label", "Platform for the fix snippet");
    var tabEls = [];
    var panels = [];
    var active = ctx.activePlatform || "nginx";

    // Select tab `n`: update aria-selected, roving tabindex, panel visibility,
    // remember the choice globally, and (when requested) move focus to the tab —
    // the WAI-ARIA tablist keyboard pattern.
    function select(n, moveFocus) {
      for (var t = 0; t < tabEls.length; t++) {
        var on = t === n;
        tabEls[t].setAttribute("aria-selected", on ? "true" : "false");
        tabEls[t].tabIndex = on ? 0 : -1;
        panels[t].hidden = !on;
      }
      ctx.activePlatform = PLATFORMS[n].id;
      if (moveFocus && tabEls[n]) tabEls[n].focus();
    }

    for (var i = 0; i < PLATFORMS.length; i++) {
      (function (plat, idx, isActive) {
        var tabId = nextId("fixtab");
        var panelId = nextId("fixpanel");

        var tab = el("button", "fix-tab");
        tab.type = "button";
        tab.id = tabId;
        tab.textContent = plat.label;
        tab.setAttribute("role", "tab");
        tab.setAttribute("aria-selected", isActive ? "true" : "false");
        tab.setAttribute("aria-controls", panelId);
        tab.tabIndex = isActive ? 0 : -1; // roving tabindex
        tabs.appendChild(tab);

        var panel = el("div", "fix-panel");
        panel.id = panelId;
        panel.setAttribute("role", "tabpanel");
        panel.setAttribute("aria-labelledby", tabId);
        panel.tabIndex = 0;
        if (!isActive) panel.hidden = true;

        var snippetText = finding.fixes[plat.id] || "";
        var row = el("div", "snippet-row");
        var pre = el("pre", "code-snippet");
        pre.appendChild(document.createTextNode(snippetText)); // author constant; textContent-safe
        row.appendChild(pre);
        var copyBtn = el("button", "copy-button");
        copyBtn.type = "button";
        copyBtn.appendChild(svgIcon(["M8 4v12a2 2 0 0 0 2 2h8", "M16 4H10a2 2 0 0 0-2 2v0", "M20 8h-8a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2v-8a2 2 0 0 0-2-2z"]));
        copyBtn.appendChild(el("span", null, "Copy"));
        copyBtn.addEventListener("click", function () { copyText(snippetText, copyBtn, "Copy"); });
        row.appendChild(copyBtn);
        panel.appendChild(row);

        tab.addEventListener("click", function () { select(idx, false); });
        tab.addEventListener("keydown", function (ev) {
          var n = null;
          switch (ev.key) {
            case "ArrowRight":
            case "ArrowDown": n = (idx + 1) % tabEls.length; break;
            case "ArrowLeft":
            case "ArrowUp":   n = (idx - 1 + tabEls.length) % tabEls.length; break;
            case "Home":      n = 0; break;
            case "End":       n = tabEls.length - 1; break;
            default: return;
          }
          ev.preventDefault();
          select(n, true);
        });

        tabEls.push(tab);
        panels.push(panel);
        fix.appendChild(panel);
      })(PLATFORMS[i], i, PLATFORMS[i].id === active);
    }

    // Insert tabs before panels.
    fix.insertBefore(tabs, fix.children[1] || null);
    return fix;
  }

  /* ================================================================== *
   * Plain-text report for the clipboard.
   * ================================================================== */
  function buildReport(graded, meta) {
    var lines = [];
    lines.push("HardenCheck report card");
    if (meta && meta.target) lines.push("Target: " + meta.target);
    lines.push("Grade: " + graded.grade + "  (" + graded.score + "/100)  — " + gradeVerdict(graded.grade, graded.counts));
    var c = graded.counts;
    lines.push("Issues: " + c.critical + " critical, " + c.high + " high, " + c.medium + " medium, " + c.low + " low | " + c.pass + " passing");
    lines.push("");
    lines.push("----------------------------------------");

    var all = graded.findings.concat(graded.cookieFindings);
    var issues = all.filter(function (f) { return f.severity !== "pass"; });
    issues.sort(function (a, b) { return ISSUE_SEVERITIES.indexOf(a.severity) - ISSUE_SEVERITIES.indexOf(b.severity); });

    if (!issues.length) {
      lines.push("No issues — every checked header and cookie flag is well-configured.");
    }
    for (var i = 0; i < issues.length; i++) {
      var x = issues[i];
      lines.push("");
      lines.push("[" + SEV_LABEL[x.severity].toUpperCase() + "] " + x.title);
      lines.push("  Observed: " + (x.observed == null ? "(header not present)" : x.observed));
      lines.push("  Risk:     " + x.detail);
      if (x.fixes) {
        lines.push("  Fix (nginx):  " + x.fixes.nginx);
      }
    }

    var passes = all.filter(function (f) { return f.severity === "pass"; });
    if (passes.length) {
      lines.push("");
      lines.push("----------------------------------------");
      lines.push("Passing: " + passes.map(function (p) { return p.title; }).join(", "));
    }

    lines.push("");
    lines.push("----------------------------------------");
    lines.push("Generated by HardenCheck (hardencheck) — a Copper Bay Labs product.");
    lines.push("A hardening check, not a full security audit or guarantee.");
    return lines.join("\n");
  }

  /* ================================================================== *
   * Clipboard copy — local only, no network.
   * ================================================================== */
  function copyText(text, btn, original) {
    function done(ok) {
      var span = btn.querySelector("span:last-child");
      var prev = span ? span.textContent : null;
      if (span) span.textContent = ok ? "Copied" : "Failed";
      btn.classList.toggle("copied", ok);
      setTimeout(function () {
        if (span) span.textContent = original;
        btn.classList.remove("copied");
      }, 1700);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { fallbackCopy(text, done); });
    } else {
      fallbackCopy(text, done);
    }
  }
  function fallbackCopy(text, done) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-1000px";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand && document.execCommand("copy");
      document.body.removeChild(ta);
      done(!!ok);
    } catch (err) {
      done(false);
    }
  }

  function renderError(results, liveRegion, message) {
    results.textContent = "";
    var box = el("div", "empty-state scan-error");
    box.appendChild(el("div", "es-icon", "!"));
    box.appendChild(el("h3", null, "Couldn't complete the check"));
    box.appendChild(el("p", null, message));
    results.appendChild(box);
    results.hidden = false;
    announce(liveRegion, "Check could not complete. " + message);
    focusResults(results);
  }

  function focusResults(results) {
    if (typeof results.focus === "function") results.focus();
    if (typeof results.scrollIntoView === "function") {
      results.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }

  /* ================================================================== *
   * Example raw header block — a realistic but under-hardened response so the
   * demo always works offline. It ships a couple of good headers (nosniff,
   * Referrer-Policy) and one well-flagged cookie, but is missing both CSP and
   * HSTS and has a weak session cookie — so it grades F with critical findings,
   * exactly the kind of result the tool is built to catch and explain.
   * ================================================================== */
  var EXAMPLE = [
    "HTTP/2 200",
    "server: nginx/1.24.0",
    "date: Mon, 08 Jun 2026 12:00:00 GMT",
    "content-type: text/html; charset=UTF-8",
    "x-powered-by: Express",
    "x-content-type-options: nosniff",
    "referrer-policy: strict-origin-when-cross-origin",
    "set-cookie: session=ab12cd34ef56; Path=/; HttpOnly",
    "set-cookie: theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax",
    "cache-control: no-store"
  ].join("\n");

  /* ================================================================== *
   * Scan orchestration.
   * ================================================================== */
  function gradePasted(text, ui) {
    var parsed = parseHeaderBlock(text);
    // Guard: if the paste had no recognizable header lines at all, tell them.
    if (Object.keys(parsed.map).length === 0 && parsed.cookies.length === 0) {
      renderError(ui.results, ui.liveRegion,
        "That didn't look like an HTTP response header block. Paste lines like \"Content-Security-Policy: ...\" — for example the output of `curl -I https://your-site.com`, or copy the Response Headers from your browser's DevTools Network tab.");
      return;
    }
    var graded = gradeAll(parsed);
    ui.last = { graded: graded, meta: { target: "Pasted headers" } };
    render(graded, ui.last.meta, ui.results, ui.liveRegion, ui.ctx);
    focusResults(ui.results);
  }

  function gradeUrl(rawUrl, ui) {
    var pageUrl = normalizeUrl(rawUrl);
    if (!pageUrl) {
      renderError(ui.results, ui.liveRegion,
        "That doesn't look like a valid URL. Enter something like https://your-site.com — or use the paste mode below.");
      return;
    }
    renderProgress(ui.results, "Fetching headers for " + pageUrl.host + "…");

    fetchHeaders(pageUrl.href).then(function (res) {
      var parsed = parseHeaderBlock(res.headerText);
      var gradedHeaderCount = 0;
      for (var i = 0; i < CHECKS.length; i++) if (CHECKS[i].key in parsed.map) gradedHeaderCount++;

      // Detect the common case where a proxy returned a response but stripped
      // every security-relevant header. Don't fabricate an "F" — be honest.
      if (gradedHeaderCount === 0 && parsed.cookies.length === 0) {
        renderError(ui.results, ui.liveRegion,
          "Reached " + pageUrl.host + ", but the public CORS proxy stripped the response headers, so there's nothing reliable to grade. This is a limitation of proxy fetching, not a verdict that your headers are missing. Use the paste mode below: run `curl -I " + pageUrl.href + "` (or copy the Response Headers from DevTools) and paste them in for an accurate grade.");
        return;
      }

      var graded = gradeAll(parsed);
      ui.last = { graded: graded, meta: { target: pageUrl.href, via: res.via } };
      render(graded, ui.last.meta, ui.results, ui.liveRegion, ui.ctx);
      focusResults(ui.results);
    }).catch(function () {
      renderError(ui.results, ui.liveRegion,
        "Couldn't reach " + pageUrl.host + " through the public CORS proxy (it may be rate-limited, down, or the site may block it). Nothing was hung or retried forever. Try again in a moment, or use the paste mode below — run `curl -I " + pageUrl.href + "` and paste the headers for a fully offline, accurate grade.");
    });
  }

  /* ================================================================== *
   * Wire-up.
   * ================================================================== */
  function init() {
    var form = document.getElementById("scan-form");
    var urlInput = document.getElementById("url");
    var pasteInput = document.getElementById("paste");
    var results = document.getElementById("results");
    var exampleBtn = document.getElementById("example-btn");
    var clearBtn = document.getElementById("clear-btn");
    var pasteToggle = document.getElementById("paste-toggle");
    var pasteWrap = document.getElementById("paste-wrap");

    if (!form || !results) return;

    var liveRegion = document.getElementById("scan-status");
    if (!liveRegion) {
      liveRegion = el("div", "sr-only");
      liveRegion.id = "scan-status";
      liveRegion.setAttribute("aria-live", "polite");
      liveRegion.setAttribute("role", "status");
      results.parentNode.insertBefore(liveRegion, results);
    }

    var ui = {
      results: results,
      liveRegion: liveRegion,
      last: null,
      ctx: { activePlatform: "nginx" }
    };

    function setPasteMode(on, opts) {
      opts = opts || {};
      if (pasteWrap) pasteWrap.hidden = !on;
      if (pasteToggle) pasteToggle.setAttribute("aria-expanded", on ? "true" : "false");
      form.setAttribute("data-mode", on ? "paste" : "url");
      if (opts.focus) {
        if (on && pasteInput) pasteInput.focus();
        else if (!on && urlInput) urlInput.focus();
      }
    }

    function currentMode() {
      var m = form.getAttribute("data-mode");
      if (m === "paste" || m === "url") return m;
      if (pasteInput && pasteInput.value.trim()) return "paste";
      return "url";
    }

    if (pasteToggle && pasteWrap) {
      setPasteMode(false);
      pasteToggle.addEventListener("click", function (e) {
        e.preventDefault();
        setPasteMode(pasteWrap.hidden, { focus: true });
      });
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var mode = currentMode();
      if (mode === "paste") {
        var pasted = pasteInput ? pasteInput.value : "";
        if (!pasted.trim()) {
          renderError(results, liveRegion, "Paste a raw HTTP response header block first (e.g. the output of `curl -I https://your-site.com`), or switch to URL mode.");
          return;
        }
        gradePasted(pasted, ui);
      } else {
        var raw = urlInput ? urlInput.value : "";
        if (!raw.trim()) {
          renderError(results, liveRegion, "Enter the URL of a site you own (e.g. https://your-site.com), or switch to paste mode.");
          return;
        }
        gradeUrl(raw, ui);
      }
    });

    if (exampleBtn) {
      exampleBtn.addEventListener("click", function (e) {
        e.preventDefault();
        if (pasteInput) {
          pasteInput.value = EXAMPLE;
          setPasteMode(true);
        }
        gradePasted(EXAMPLE, ui);
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", function (e) {
        e.preventDefault();
        if (urlInput) urlInput.value = "";
        if (pasteInput) pasteInput.value = "";
        if (pasteToggle && pasteWrap) setPasteMode(false);
        ui.last = null;
        results.textContent = "";
        results.hidden = true;
        announce(liveRegion, "Cleared. Enter a URL or paste headers to check again.");
        if (urlInput) urlInput.focus();
        else if (pasteInput) pasteInput.focus();
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
