# HardenCheck

**Check your site for missing security headers and unsafe cookies — in plain English, in your browser.**

HardenCheck grades a site's HTTP response headers and `Set-Cookie` flags into a
screenshot-worthy **A–F report card**, with a per-header findings list ranked by
severity and **copy-paste fixes for nginx, Apache, Vercel, and Next.js**.

It is part of the [Copper Bay Labs](https://copperbaytech.com) ship-safety suite
(alongside [LeakCheck](https://dukotah.github.io/leakcheck/),
[ExposureCheck](https://dukotah.github.io/exposurecheck/),
[DepCheck](https://dukotah.github.io/depcheck/), and
[ShipSafe](https://dukotah.github.io/shipsafe/)).

## What it checks

- **Content-Security-Policy** — presence + `'unsafe-inline'` / `'unsafe-eval'` / wildcard weaknesses
- **Strict-Transport-Security (HSTS)** — presence + `max-age` strength
- **X-Frame-Options** — clickjacking protection (also reads CSP `frame-ancestors`)
- **X-Content-Type-Options** — `nosniff`
- **Referrer-Policy** — privacy of the `Referer` header
- **Permissions-Policy** — disabling unused powerful browser features
- **Cross-Origin-Opener-Policy** and **Cross-Origin-Resource-Policy**
- **Cookie flags** — every `Set-Cookie` is checked for `Secure`, `HttpOnly`, `SameSite`
- **Information disclosure** — `Server`, `X-Powered-By`, and similar stack-revealing headers

## Two modes

1. **URL mode** — fetches the target through a public CORS-proxy chain and reads
   whatever response headers the proxy exposes. Public proxies often strip
   headers; when that happens HardenCheck says so honestly rather than awarding a
   fake failing grade. It never hangs (per-request timeouts + a fallback to a
   direct fetch).
2. **Paste mode** (always works, no network) — paste a raw HTTP response header
   block, e.g. the output of `curl -I https://your-site.com` or the *Response
   Headers* copied from your browser's DevTools Network tab. This is the most
   accurate path.

## How the grade works

Start at 100. Subtract per issue: Critical −25, High −16, Medium −9, Low −4.
Letter: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 45, F otherwise. (Heuristic, not an
industry-standard score.)

## Privacy & security

- 100% client-side. No backend, no API keys, no analytics on your input.
- Paste mode makes **no** network request at all.
- URL mode's only network call is the proxy fetch of the target URL.
- All fetched/pasted text reaches the DOM via `textContent` only — never
  `innerHTML` — so it cannot inject markup or run script. Fix snippets are
  author-controlled constants.
- Cookie **values** are never shown — only names and flags.

## Files

| File | Purpose |
| --- | --- |
| `index.html` | Landing page + the scanner tool |
| `app.js` | Header/cookie grading engine, proxy fetch, report-card render |
| `styles.css` | Copper Bay Labs design system + report-card styling |
| `about.html` | Methodology, grading, proxy limits, privacy |
| `404.html` | Not-found page |
| `favicon.svg` | Shield + check mark mark |
| `og-template.html` | 1200×630 social-card template (render to `og-image.png`) |
| `robots.txt`, `sitemap.xml` | SEO |
| `BUILD-NOTES.md` | What shipped, the parked PulseGuard tier, limitations, follow-ups |

## Running locally

It's a static site — open `index.html`, or serve the folder:

```sh
python3 -m http.server 8000
# then visit http://localhost:8000/
```

## Disclaimer

HardenCheck grades HTTP response headers and cookie flags only. It is a fast
hardening check, **not a full security audit, certification, or guarantee, and
not professional security advice.** A clean grade does not mean your site is
secure.

A Copper Bay Labs product.
