# Browser-Fingerprint

Uses browser-based capabilities to identify browser, OS, hardware, and other
device details to generate a unique user fingerprint for that web browser.

[![GitHub tag](https://img.shields.io/github/tag/soren42/browser-fingerprint?include_prereleases=&sort=semver&color=blue)](https://github.com/soren42/browser-fingerprint/releases/)
[![License](https://img.shields.io/badge/License-MIT-blue)](#license)
![Static Badge](https://img.shields.io/badge/php_8.x-white?style=flat&logo=php)

## What it is

A dependency-free page (PHP + vanilla CSS/JS, no CDN calls) intended for
**private intranet use**. It collects:

- HTTP headers & server variables (server-side, via PHP)
- UA Client Hints (high-entropy values, plus server-requested `Accept-CH`)
- Canvas 2D, WebGL/WebGL2 render hashes, GPU renderer/vendor
- Audio fingerprint (OfflineAudioContext)
- Installed-font detection (multi-baseline width measurement)
- Locale, timezone, Intl data, network info, battery, storage, media devices,
  speech voices, permissions, WebRTC host candidates
- CSS media features & a ~90-entry JS API feature matrix
- Math/FPU fingerprint, performance timing, input capabilities
- Engine-specific probes: WebKit/Safari, Chromium/Edge, Firefox/Gecko
  (including Resist-Fingerprinting detection)

It then derives a **stable master fingerprint** (device-level signals only) and
a **session hash** (adds volatile signals like IP and battery), renders a
10-cell intelligence summary bar with confidence indicators, and offers
one-click **JSON export** of the full report.

## Files

| File | Purpose |
|---|---|
| `index.php` | Audited default entry point; waits for all collectors before hashing |
| `fingerprint.php` | Original PHP server collection + HTML shell + CSS theme |
| `assets/browserprint.core.js` | Collectors for sections 1–21 |
| `assets/browserprint.app.js` | Engine probes, intel bar, hashing, original orchestration |
| `assets/browserprint.audit-fixes.js` | Review compatibility layer fixing async orchestration |
| `docs/code-audit-2026-07-19.html` | Self-contained source audit and improvement roadmap |

## Usage

Upload the folder to any PHP 8+ web server and open `index.php` in a browser.
No build step, no Composer, no external assets.

`fingerprint.php` remains available as the original direct entry point, but
`index.php` is preferred because it waits for every asynchronous collector
before computing the hashes and marking the scan complete.

> **Note:** several probes (UA Client Hints, `enumerateDevices`, clipboard)
> require a secure context. Serve over HTTPS for full coverage.

## Security and privacy

This application intentionally gathers high-entropy browser and device data.
Keep it on a trusted private network unless you have reviewed the server-data
exposure, consent model, output escaping, Content Security Policy, and export
handling described in the audit report.

## Documentation

[![view - Documentation](https://img.shields.io/badge/view-Documentation-blue?style=for-the-badge)](/docs/ "Go to project documentation")

## License

Released under [MIT](/LICENSE) by [@soren42](https://github.com/soren42).
