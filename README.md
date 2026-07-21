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

New in v4.2: an **AI Analyst Summary** card that reads the collected report
and writes a one-paragraph deduction — likely browser/version, OS, hardware,
visible plug-ins, and blind spots caused by filtering or obfuscation.

## Files

| File | Purpose |
|---|---|
| `fingerprint.php` | **The whole application** — PHP collection, HTML, CSS, and JS in one monolithic file |
| `index.php` | Thin alias that `require`s `fingerprint.php` so `/` also serves the tool |
| `docs/code-audit-2026-07-19.html` | Self-contained source audit and improvement roadmap |

The application returned to its original single-file remit in v4.2. The
readable, commented JS sources that previously lived in `assets/` remain
available in the git history (tag/commit prior to the v4.2 merge).

## Usage

Upload `fingerprint.php` (and optionally `index.php`) to any PHP 8+ web
server and open it in a browser. No build step, no Composer, no external
assets.

> **Note:** several probes (UA Client Hints, `enumerateDevices`, clipboard)
> require a secure context. Serve over HTTPS for full coverage.

## AI analyst configuration

Out of the box the summary card uses a built-in **local heuristic engine** —
no network calls, no keys. To get LLM-written analysis instead, edit the
`$BP_AI` block at the top of `fingerprint.php`:

```php
$BP_AI = [
    'enabled'  => true,
    'endpoint' => 'https://api.openai.com/v1/chat/completions', // any OpenAI-compatible API
    'api_key'  => 'sk-...',          // stays server-side, never sent to the browser
    'model'    => 'gpt-4o-mini',     // inexpensive model is plenty
    'timeout'  => 20,
];
```

Any OpenAI-compatible chat-completions endpoint works — including local,
zero-cost servers such as Ollama (`http://localhost:11434/v1/chat/completions`,
model e.g. `llama3.1`) or LM Studio. The page POSTs a compact JSON report to
`?action=ai-summary` on the same file; PHP forwards it to the configured
endpoint and returns one paragraph. If the endpoint is unconfigured, offline,
or errors, the card silently falls back to the local heuristic engine and
labels which source produced the text.

## Security and privacy

This application intentionally gathers high-entropy browser and device data.
Keep it on a trusted private network unless you have reviewed the server-data
exposure, consent model, output escaping, Content Security Policy, and export
handling described in the audit report. If you enable the AI endpoint, the
collected report is sent to that third-party (or local) API — choose it
accordingly.

## Documentation

[![view - Documentation](https://img.shields.io/badge/view-Documentation-blue?style=for-the-badge)](/docs/ "Go to project documentation")

## License

Released under [MIT](/LICENSE) by [@soren42](https://github.com/soren42).
