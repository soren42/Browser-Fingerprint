# Browser-Fingerprint

Uses browser-based capabilities to identify browser, OS, hardware, and other
device details to generate a unique user fingerprint for that web browser.

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
| `fingerprint.php` | PHP server collection + HTML shell + CSS theme |
| `assets/browserprint.core.js` | Collectors for sections 1–21 |
| `assets/browserprint.app.js` | Engine probes, intel bar, hashing, orchestration |

## Usage

Upload the folder to any PHP 8+ web server and open `fingerprint.php` in a
browser. No build step, no Composer, no external assets.

> **Note:** several probes (UA Client Hints, `enumerateDevices`, clipboard)
> require a secure context. Serve over HTTPS for full coverage.
