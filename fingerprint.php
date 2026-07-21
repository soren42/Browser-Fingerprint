<?php
/**
 * browserprint.php — Comprehensive Browser & System Fingerprinting Tool
 * For private intranet use only. Jason C. Kay / solarian design
 *
 * Collects every available signal: HTTP headers, UA client hints, canvas,
 * WebGL, audio, fonts, WebRTC, battery, media, permissions, CSS features,
 * math/FPU variance, performance, storage, speech synthesis, and more.
 */

// ── AI Analyst Configuration ──────────────────────────────────────────────
// The AI summary endpoint proxies the collected fingerprint to any
// OpenAI-compatible chat-completions API (OpenAI, Azure, Ollama, LM Studio…).
// The API key lives ONLY here on the server — it is never sent to the browser.
// Leave 'endpoint' empty to disable the remote call: the page then falls back
// to its built-in heuristic deduction engine automatically.
$BP_AI = [
    'enabled'  => true,
    'endpoint' => '',               // e.g. 'https://api.openai.com/v1/chat/completions'
                                    // or   'http://localhost:11434/v1/chat/completions' (Ollama)
    'api_key'  => '',               // server-side secret — never echoed to the page
    'model'    => 'gpt-4o-mini',    // any inexpensive model works ('llama3.1' for Ollama)
    'timeout'  => 20,               // seconds
];

// ── AI Summary Endpoint (same file, ?action=ai-summary) ───────────────────
if (($_GET['action'] ?? '') === 'ai-summary') {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        echo json_encode(['ok' => false, 'error' => 'POST required']);
        exit;
    }
    $raw = file_get_contents('php://input') ?: '';
    if (strlen($raw) > 262144) {                       // 256 KB cap
        http_response_code(413);
        echo json_encode(['ok' => false, 'error' => 'payload too large']);
        exit;
    }
    $payload = json_decode($raw, true);
    if (!is_array($payload) || empty($payload['report'])) {
        http_response_code(400);
        echo json_encode(['ok' => false, 'error' => 'invalid payload']);
        exit;
    }
    if (!$BP_AI['enabled'] || $BP_AI['endpoint'] === '') {
        // Not an error — tells the client to use its local heuristic engine
        echo json_encode(['ok' => false, 'error' => 'unconfigured']);
        exit;
    }

    $system = 'You are a senior browser-fingerprinting analyst and browser engine programmer. '
            . 'Given a JSON browser fingerprint, respond with ONE concise paragraph (max ~120 words) '
            . 'of deductions: most likely browser + version, engine, OS + version, CPU architecture, '
            . 'device class, GPU/hardware, notable plugins or capabilities, and any blind spots or '
            . 'signs of obfuscation/anti-fingerprinting (masked renderers, RFP noise, missing APIs, '
            . 'secure-context limitations). Be direct and specific; no disclaimers, no lists.';
    $user = 'Fingerprint report JSON:
' . json_encode($payload['report']);

    $reqBody = json_encode([
        'model'       => $BP_AI['model'],
        'messages'    => [
            ['role' => 'system', 'content' => $system],
            ['role' => 'user',   'content' => $user],
        ],
        'max_tokens'  => 400,
        'temperature' => 0.3,
    ]);

    $headers = ['Content-Type: application/json'];
    if ($BP_AI['api_key'] !== '') $headers[] = 'Authorization: Bearer ' . $BP_AI['api_key'];

    $resp = false; $err = '';
    if (function_exists('curl_init')) {
        $ch = curl_init($BP_AI['endpoint']);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $reqBody,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => (int)$BP_AI['timeout'],
        ]);
        $resp = curl_exec($ch);
        $err  = curl_error($ch);
        curl_close($ch);
    } else {
        $ctx = stream_context_create(['http' => [
            'method'  => 'POST',
            'header'  => implode("\r\n", $headers),
            'content' => $reqBody,
            'timeout' => (int)$BP_AI['timeout'],
        ]]);
        $resp = @file_get_contents($BP_AI['endpoint'], false, $ctx);
        if ($resp === false) $err = 'request failed (streams)';
    }

    if ($resp === false) {
        echo json_encode(['ok' => false, 'error' => 'upstream: ' . $err]);
        exit;
    }
    $data = json_decode($resp, true);
    $text = $data['choices'][0]['message']['content'] ?? null;
    if (!$text) {
        echo json_encode(['ok' => false, 'error' => 'bad upstream response']);
        exit;
    }
    echo json_encode(['ok' => true, 'summary' => trim($text), 'model' => $BP_AI['model']]);
    exit;
}

// ── Server-Side Collection ────────────────────────────────────────────────

// Response hardening
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');

// Request high-entropy UA Client Hints on subsequent requests (Chromium only).
// Without Accept-CH the server never receives Sec-CH-UA-* headers at all.
header('Accept-CH: Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Model, Sec-CH-UA-Full-Version-List, Sec-CH-UA-WoW64');
header('Critical-CH: Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version');

$all_headers  = function_exists('getallheaders') ? getallheaders() : [];
$server_clean = [];
foreach ($_SERVER as $k => $v) {
    if (is_string($v) || is_numeric($v)) {
        $server_clean[$k] = $v;
    }
}

$php_payload = json_encode([
    'headers'         => $all_headers,
    'server'          => $server_clean,
    'php_version'     => PHP_VERSION,
    'php_os'          => PHP_OS,
    'php_sapi'        => PHP_SAPI,
    'php_int_size'    => PHP_INT_SIZE,
    'timestamp_utc'   => gmdate('Y-m-d\TH:i:s\Z'),
    'request_method'  => $_SERVER['REQUEST_METHOD'] ?? '',
    'remote_addr'     => $_SERVER['REMOTE_ADDR'] ?? '',
    'forwarded_for'   => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
    'real_ip'         => $_SERVER['HTTP_X_REAL_IP'] ?? '',
    'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? '',
    'server_protocol' => $_SERVER['SERVER_PROTOCOL'] ?? '',
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
if ($php_payload === false) {
    // Never emit an invalid JS literal into the page
    $php_payload = '{"error":"json_encode failed","headers":{},"server":{}}';
}

?><!DOCTYPE html>

<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BrowserPrint // Intranet Fingerprinting Suite</title>
<style>:root{--bg:#090c10;--bg2:#0d1117;--bg3:#161b22;--border:#21262d;--green:#39d353;--green-dim:#1a6b26;--cyan:#58d4f0;--cyan-dim:#1e5a6e;--yellow:#e3b341;--red:#f85149;--purple:#bc8cff;--text:#c9d1d9;--text-dim:#6e7681;--glow:0 0 8px rgba(57,211,83,0.35);--glow-c:0 0 8px rgba(88,212,240,0.35)}*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}html{scroll-behavior:smooth}body{background-color:#090c10;color:#c9d1d9;font-family:'Consolas','Fira Code','Courier New',monospace;font-size:13px;line-height:1.6;min-height:100vh;padding:0 0 60px 0;background-image:radial-gradient(ellipse at 20% 0%,rgba(57,211,83,0.04) 0%,transparent 60%),radial-gradient(ellipse at 80% 100%,rgba(88,212,240,0.03) 0%,transparent 60%)}#masthead{background:#0d1117;border-bottom:1px solid #21262d;padding:24px 32px 20px;position:sticky;top:0;z-index:100;-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px)}#masthead h1{font-family:'Consolas','Lucida Console',monospace;letter-spacing:0.06em;font-size:18px;font-weight:900;letter-spacing:0.12em;color:#39d353;text-shadow:0 0 8px rgba(57,211,83,0.35);display:flex;align-items:center;gap:12px}#masthead h1 span.ver{font-size:10px;color:#6e7681;font-family:'Consolas','Courier New',monospace;font-weight:400;letter-spacing:0.05em}#hash-bar{margin-top:10px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}#hash-bar .label{color:#6e7681;font-size:11px;text-transform:uppercase;letter-spacing:0.1em}#master-hash{font-family:'Consolas','Lucida Console',monospace;letter-spacing:0.06em;font-size:13px;font-weight:700;color:#58d4f0;text-shadow:0 0 8px rgba(88,212,240,0.35);letter-spacing:0.06em}#hash-bar2{margin-top:4px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:11px}
#hash-bar2 .label{color:#6e7681;font-size:10px;text-transform:uppercase;letter-spacing:0.1em}#session-hash{font-family:'Consolas','Lucida Console',monospace;font-size:11px;color:#6e7681}.hash-btn{background:none;border:1px solid #21262d;border-radius:4px;color:#6e7681;cursor:pointer;font-family:inherit;font-size:10px;padding:2px 8px;letter-spacing:0.05em;transition:border-color 0.15s,color 0.15s}.hash-btn:hover{border-color:#39d353;color:#39d353}html.light .hash-btn{border-color:#d0d7de;color:#57606a}html.light .hash-btn:hover{border-color:#1a7f37;color:#1a7f37}#status-bar{margin-top:8px;display:flex;gap:16px;flex-wrap:wrap}.status-chip{font-size:11px;padding:2px 8px;border-radius:3px;border:1px solid;display:inline-flex;align-items:center;gap:5px}.status-chip.ok{border-color:#1a6b26;color:#39d353}.status-chip.warn{border-color:#6b4a00;color:#e3b341}.status-chip.err{border-color:#6b1c1c;color:#f85149}.status-chip.info{border-color:#1e5a6e;color:#58d4f0}#container{max-width:1200px;margin:0 auto;padding:24px 32px;display:flex;flex-direction:column;gap:12px}.section{background:#0d1117;border:1px solid #21262d;border-radius:6px;overflow:hidden;transition:border-color 0.2s}.section:hover{border-color:#30363d}.section-header{display:flex;align-items:center;gap:10px;padding:10px 16px;background:#161b22;cursor:pointer;user-select:none;border-bottom:1px solid #21262d;transition:background 0.15s}.section-header:hover{background:#1c2128}.section-header .icon{font-size:15px}.section-header .title{font-family:'Consolas','Lucida Console',monospace;letter-spacing:0.06em;font-size:11px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;color:#58d4f0;flex:1}
.section-header .count{font-size:10px;color:#6e7681;background:#1a1f27;padding:1px 6px;border-radius:10px;border:1px solid #21262d}.toggle-arrow{color:#6e7681;font-size:10px;transition:transform 0.2s}.section.collapsed .toggle-arrow{transform:rotate(-90deg)}.section-body{padding:14px 16px;display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:6px 20px}.section.collapsed .section-body{display:none}.section-body.single-col{grid-template-columns:1fr}.section-body.two-col{grid-template-columns:repeat(2,1fr)}.row{display:flex;gap:8px;min-height:22px;align-items:flex-start;border-bottom:1px solid rgba(33,38,45,0.5);padding-bottom:3px}.row:last-child{border-bottom:none}.row-key{color:#6e7681;font-size:11px;min-width:200px;flex-shrink:0;padding-top:1px;text-overflow:ellipsis;overflow:hidden;white-space:nowrap}.row-val{color:#c9d1d9;font-size:12px;word-break:break-all;flex:1}.row-val.green{color:#39d353}.row-val.cyan{color:#58d4f0}.row-val.yellow{color:#e3b341}.row-val.red{color:#f85149}.row-val.purple{color:#bc8cff}.row-val.dim{color:#6e7681}.tag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;margin:1px 2px 1px 0;border:1px solid}.tag.yes{border-color:#1a6b26;color:#39d353;background:rgba(57,211,83,0.06)}.tag.no{border-color:#3d1a1a;color:#f85149;background:rgba(248,81,73,0.06)}.tag.item{border-color:#1e5a6e;color:#58d4f0;background:rgba(88,212,240,0.06)}.tag.warn{border-color:#6b4a00;color:#e3b341;background:rgba(227,179,65,0.06)}#canvas-preview-wrap{grid-column:1 / -1;display:flex;align-items:center;gap:16px;padding:8px 0;border-bottom:1px solid rgba(33,38,45,0.5)}#canvas-preview-wrap canvas{border:1px solid #21262d;border-radius:4px;image-rendering:pixelated}
#font-grid{grid-column:1 / -1;display:flex;flex-wrap:wrap;gap:4px;padding:4px 0}.raw-block{grid-column:1 / -1;background:#161b22;border:1px solid #21262d;border-radius:4px;padding:10px 12px;font-size:11px;color:#6e7681;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto}.progress-wrap{grid-column:1 / -1;margin:4px 0}.progress-label{font-size:11px;color:#6e7681;margin-bottom:4px}.progress-bar{height:4px;background:#161b22;border-radius:2px;overflow:hidden}.progress-fill{height:100%;background:linear-gradient(90deg,#39d353,#58d4f0);transition:width 0.4s ease;box-shadow:0 0 6px rgba(57,211,83,0.5)}::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:#0d1117}::-webkit-scrollbar-thumb{background:#30363d;border-radius:3px}::-webkit-scrollbar-thumb:hover{background:#484f58}#loader{position:fixed;inset:0;background:#090c10;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;z-index:9999;transition:opacity 0.4s ease}#loader.done{opacity:0;pointer-events:none}#loader h2{font-family:'Consolas','Lucida Console',monospace;letter-spacing:0.06em;font-size:14px;color:#39d353;letter-spacing:0.15em;text-shadow:0 0 8px rgba(57,211,83,0.35);animation:pulse 1.2s ease-in-out infinite}#loader-bar{width:260px;height:2px;background:#1a2030;border-radius:1px;overflow:hidden}#loader-fill{height:100%;width:0%;background:linear-gradient(90deg,#39d353,#58d4f0);transition:width 0.15s linear;box-shadow:0 0 8px rgba(57,211,83,0.6)}#loader-msg{font-size:11px;color:#6e7681;min-height:16px;letter-spacing:0.05em}@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.6}}.intel-cell{background:#0d1117}#intel-bar{background:#161b22}.raw-block{background:#161b22}.progress-bar{background:#161b22}
.section-header .count{background:#0d1117}body{color:#c9d1d9}#masthead h1{color:#39d353;text-shadow:0 0 8px rgba(57,211,83,0.35)}#masthead h1 span.ver{color:#6e7681}#hash-bar .label{color:#6e7681}#master-hash{color:#58d4f0;text-shadow:0 0 8px rgba(88,212,240,0.35)}#theme-toggle{border-color:#21262d;color:#6e7681}#theme-toggle:hover{border-color:#58d4f0;color:#58d4f0}.status-chip.ok{border-color:#1a6b26;color:#39d353}.status-chip.warn{border-color:#6b4a00;color:#e3b341}.status-chip.err{border-color:#6b1c1c;color:#f85149}.status-chip.info{border-color:#1e5a6e;color:#58d4f0}.section{border-color:#21262d}.section-header{border-bottom-color:#21262d}.section-header .title{color:#58d4f0}.section-header .count{color:#6e7681;background:#0d1117;border-color:#21262d}.toggle-arrow{color:#6e7681}.section-header:hover{background:#1c2128}.row-key{color:#6e7681}.row-val{color:#c9d1d9}.row-val.green{color:#39d353}.row-val.cyan{color:#58d4f0}.row-val.yellow{color:#e3b341}.row-val.red{color:#f85149}.row-val.purple{color:#bc8cff}.row-val.dim{color:#6e7681}.tag.yes{border-color:#1a6b26;color:#39d353;background:rgba(57,211,83,0.06)}.tag.no{border-color:#3d1a1a;color:#f85149;background:rgba(248,81,73,0.06)}.tag.item{border-color:#1e5a6e;color:#58d4f0;background:rgba(88,212,240,0.06)}.tag.warn{border-color:#6b4a00;color:#e3b341;background:rgba(227,179,65,0.06)}#intel-bar{border-color:#21262d}.intel-cell{border-right-color:#21262d}.intel-label{color:#6e7681}.intel-value{color:#c9d1d9}.intel-sub{color:#6e7681}.intel-conf.high{background:#39d353;box-shadow:0 0 6px rgba(57,211,83,0.4)}.intel-conf.medium{background:#e3b341;box-shadow:0 0 6px rgba(227,179,65,0.35)}.intel-conf.low{background:#f85149;box-shadow:0 0 6px rgba(248,81,73,0.3)}.intel-conf.none{background:#21262d}
.raw-block{color:#6e7681;border-color:#21262d}.progress-label{color:#6e7681}.progress-fill{background:linear-gradient(90deg,#39d353,#58d4f0);box-shadow:0 0 6px rgba(57,211,83,0.5)}#loader h2{color:#39d353;text-shadow:0 0 8px rgba(57,211,83,0.35)}#loader-msg{color:#6e7681}#loader-fill{background:linear-gradient(90deg,#39d353,#58d4f0);box-shadow:0 0 8px rgba(57,211,83,0.6)}::-webkit-scrollbar-thumb{background:#30363d}::-webkit-scrollbar-thumb:hover{background:#484f58}html.light{--bg:#f0f2f5;--bg2:#ffffff;--bg3:#e8eaed;--border:#d0d7de;--green:#1a7f37;--green-dim:#b3e6c3;--cyan:#0969da;--cyan-dim:#b6d7f7;--yellow:#9a6700;--red:#cf222e;--purple:#8250df;--text:#1f2328;--text-dim:#57606a;--glow:0 0 8px rgba(26,127,55,0.2);--glow-c:0 0 8px rgba(9,105,218,0.2)}html.light body{background-color:#f0f2f5;background-image:radial-gradient(ellipse at 20% 0%,rgba(26,127,55,0.04) 0%,transparent 60%),radial-gradient(ellipse at 80% 100%,rgba(9,105,218,0.03) 0%,transparent 60%);color:#1f2328}html.light #masthead{background:rgba(255,255,255,0.95)}html.light #masthead h1{color:#1a7f37;text-shadow:none}html.light #master-hash{color:#0969da;text-shadow:none}html.light #hash-bar .label{color:#57606a}html.light #theme-toggle{border-color:#d0d7de;color:#57606a}html.light .section{background:#ffffff;border-color:#d0d7de}html.light .section-header{background:#e8eaed;border-bottom-color:#d0d7de}html.light .section-header .title{color:#0969da}html.light .section-header .icon{color:initial}html.light .toggle-arrow{color:#57606a}html.light .section-body{background:#ffffff}html.light .row{border-bottom-color:rgba(208,215,222,0.6)}html.light .row-key{color:#57606a}html.light .row-val{color:#1f2328}html.light .row-val.green{color:#1a7f37}html.light .row-val.cyan{color:#0969da}
html.light .row-val.yellow{color:#9a6700}html.light .row-val.red{color:#cf222e}html.light .row-val.purple{color:#8250df}html.light .row-val.dim{color:#57606a}html.light #intel-bar{background:#e8eaed}html.light .intel-cell{background:#ffffff}html.light .intel-label{color:#57606a}html.light .intel-value{color:#1f2328}html.light .intel-sub{color:#57606a}html.light .intel-conf.none{background:#d0d7de}html.light .raw-block{background:#e8eaed}html.light .progress-bar{background:#e8eaed}html.light .progress-fill{background:linear-gradient(90deg,#1a7f37,#0969da);box-shadow:0 0 6px rgba(26,127,55,0.3)}html.light #canvas-preview-wrap{background:transparent}html.light #loader-msg{color:#57606a}html.light #loader{background:#f0f2f5}html.light #loader h2{color:#1a7f37;text-shadow:none}html.light #loader-bar{background:#d0d7de}html.light #loader-fill{background:linear-gradient(90deg,#1a7f37,#0969da);box-shadow:0 0 8px rgba(26,127,55,0.4)}html.light .section:hover{border-color:#b0b8c1}html.light .section-header:hover{background:#f6f8fa}html.light .raw-block{color:#57606a}html.light #masthead{background:rgba(255,255,255,0.95)}html.light .status-chip.ok{border-color:#b3e6c3;color:#1a7f37}html.light .status-chip.warn{border-color:#f5d58a;color:#9a6700}html.light .status-chip.err{border-color:#ffc1be;color:#cf222e}html.light .status-chip.info{border-color:#b6d7f7;color:#0969da}html.light .tag.yes{border-color:#b3e6c3;color:#1a7f37;background:rgba(26,127,55,0.07)}html.light .tag.no{border-color:#ffc1be;color:#cf222e;background:rgba(207,34,46,0.07)}html.light .tag.item{border-color:#b6d7f7;color:#0969da;background:rgba(9,105,218,0.07)}html.light .tag.warn{border-color:#f5d58a;color:#9a6700;background:rgba(154,103,0,0.07)}html.light #loader{background:#f0f2f5}
html.light #loader h2{color:#1a7f37}html.light #loader-bar{background:#d0d7de}html.light .section-header .count{background:#f6f8fa}html.light canvas{border-color:#d0d7de}#theme-toggle{background:none;border:1px solid #21262d;border-radius:4px;color:#6e7681;cursor:pointer;font-family:inherit;font-size:12px;padding:4px 10px;letter-spacing:0.05em;transition:border-color 0.15s,color 0.15s,background 0.15s;white-space:nowrap;display:flex;align-items:center;gap:6px}#theme-toggle:hover{border-color:#58d4f0;color:#58d4f0;background:rgba(88,212,240,0.06)}html.light #theme-toggle:hover{background:rgba(9,105,218,0.06)}#masthead-top{display:flex;align-items:center;justify-content:space-between;gap:12px}#intel-bar{margin-top:14px;display:flex;flex-wrap:wrap;gap:2px;border:1px solid #21262d;border-radius:5px;overflow:hidden;background:#161b22}.intel-cell{flex:1;min-width:110px;padding:8px 12px 0 12px;background:#0d1117;position:relative;display:flex;flex-direction:column;gap:2px;border-right:1px solid #21262d}.intel-cell:last-child{border-right:none}.intel-label{font-size:9px;text-transform:uppercase;letter-spacing:0.12em;color:#6e7681;white-space:nowrap}.intel-value{font-size:12px;font-weight:700;color:#c9d1d9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding-bottom:7px}.intel-sub{font-size:9px;color:#6e7681;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:-2px;padding-bottom:7px}.intel-conf{position:absolute;bottom:0;left:0;right:0;height:3px;border-radius:0 0 1px 1px}.intel-conf.high{background:#39d353;box-shadow:0 0 6px rgba(57,211,83,0.4)}.intel-conf.medium{background:#e3b341;box-shadow:0 0 6px rgba(227,179,65,0.35)}.intel-conf.low{background:#f85149;box-shadow:0 0 6px rgba(248,81,73,0.3)}.intel-conf.none{background:#21262d}
html.light .intel-conf.high{box-shadow:0 0 4px rgba(26,127,55,0.3)}html.light .intel-conf.medium{box-shadow:0 0 4px rgba(154,103,0,0.3)}html.light .intel-conf.low{box-shadow:0 0 4px rgba(207,34,46,0.25)}@media (max-width:900px){.intel-cell{min-width:90px}.intel-value{font-size:11px}}@media (max-width:600px){#intel-bar{flex-direction:column}.intel-cell{border-right:none;border-bottom:1px solid #21262d}.intel-cell:last-child{border-bottom:none}.intel-conf{bottom:0;height:3px}}@media (max-width:600px) and (orientation:portrait){#masthead{position:relative;padding:12px 14px 10px}#masthead h1{font-size:15px}#masthead h1 span.ver{display:none}#intel-bar{display:grid;grid-template-columns:1fr 1fr;overflow:visible;margin-top:10px}.intel-cell{border-right:1px solid #21262d;border-bottom:1px solid #21262d;min-width:0;padding:6px 8px 0 8px}.intel-cell:nth-child(even){border-right:none}.intel-cell:nth-last-child(-n+2){border-bottom:none}.intel-cell:last-child:nth-child(odd){grid-column:1 / -1;border-right:none;border-bottom:none}.intel-label{font-size:7.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.intel-value{font-size:11px;padding-bottom:6px}.intel-sub{font-size:8px;padding-bottom:6px}.intel-conf{height:2px}#hash-bar{margin-top:8px}#master-hash{font-size:11px}#status-bar{gap:8px}.status-chip{font-size:10px;padding:1px 6px}}@media (max-width:900px) and (orientation:landscape){#masthead{padding:8px 16px}#masthead h1{font-size:14px}#masthead h1 span.ver{font-size:9px}
#intel-bar{flex-wrap:nowrap;overflow-x:auto;overflow-y:visible;-webkit-overflow-scrolling:touch;scrollbar-width:thin;scrollbar-color:#21262d transparent;margin-top:8px;-webkit-mask-image:linear-gradient(to right,black 85%,transparent 100%);mask-image:linear-gradient(to right,black 85%,transparent 100%)}.intel-cell{flex:0 0 auto;min-width:88px;max-width:120px;padding:5px 10px 0 10px}.intel-label{font-size:7.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.intel-value{font-size:11px;padding-bottom:5px}.intel-sub{font-size:8px;padding-bottom:5px}.intel-conf{height:2px}#hash-bar{margin-top:6px}#status-bar{margin-top:4px;gap:8px}.status-chip{font-size:10px}}@media (max-width:768px){#container{padding:12px 16px}.section-body{grid-template-columns:1fr}.row-key{min-width:140px}}}</style>
</head>
<body>

<!-- ── Loading Screen ──────────────────────────────────────────────────── -->

<div id="loader">
  <h2>INITIALIZING SCAN</h2>
  <div id="loader-bar"><div id="loader-fill"></div></div>
  <div id="loader-msg">Enumerating browser surface...</div>
</div>

<!-- ── Masthead ─────────────────────────────────────────────────────────── -->

<div id="masthead">
  <div id="masthead-top">
    <h1>
      &#9632; BROWSERPRINT
      <span class="ver">v4.2 // intranet only // solarian design</span>
    </h1>
    <button id="theme-toggle" onclick="toggleTheme()" title="Toggle light/dark mode">
      <span id="theme-icon">☀</span><span id="theme-label">light</span>
    </button>
  </div>

  <!-- ── Intelligence Summary Bar ──────────────────────────────────────── -->

  <div id="intel-bar">
    <div class="intel-cell" id="ic-browser">
      <span class="intel-label">browser</span>
      <span class="intel-value" id="iv-browser">—</span>
      <span class="intel-sub"  id="is-browser">&nbsp;</span>
      <div class="intel-conf none" id="iconf-browser"></div>
    </div>
    <div class="intel-cell" id="ic-engine">
      <span class="intel-label">engine</span>
      <span class="intel-value" id="iv-engine">—</span>
      <span class="intel-sub"  id="is-engine">&nbsp;</span>
      <div class="intel-conf none" id="iconf-engine"></div>
    </div>
    <div class="intel-cell" id="ic-os">
      <span class="intel-label">operating system</span>
      <span class="intel-value" id="iv-os">—</span>
      <span class="intel-sub"  id="is-os">&nbsp;</span>
      <div class="intel-conf none" id="iconf-os"></div>
    </div>
    <div class="intel-cell" id="ic-arch">
      <span class="intel-label">architecture</span>
      <span class="intel-value" id="iv-arch">—</span>
      <span class="intel-sub"  id="is-arch">&nbsp;</span>
      <div class="intel-conf none" id="iconf-arch"></div>
    </div>
    <div class="intel-cell" id="ic-device">
      <span class="intel-label">device type</span>
      <span class="intel-value" id="iv-device">—</span>
      <span class="intel-sub"  id="is-device">&nbsp;</span>
      <div class="intel-conf none" id="iconf-device"></div>
    </div>
    <div class="intel-cell" id="ic-display">
      <span class="intel-label">display</span>
      <span class="intel-value" id="iv-display">—</span>
      <span class="intel-sub"  id="is-display">&nbsp;</span>
      <div class="intel-conf none" id="iconf-display"></div>
    </div>
    <div class="intel-cell" id="ic-gpu">
      <span class="intel-label">gpu / renderer</span>
      <span class="intel-value" id="iv-gpu">—</span>
      <span class="intel-sub"  id="is-gpu">&nbsp;</span>
      <div class="intel-conf none" id="iconf-gpu"></div>
    </div>
    <div class="intel-cell" id="ic-hw">
      <span class="intel-label">hardware</span>
      <span class="intel-value" id="iv-hw">—</span>
      <span class="intel-sub"  id="is-hw">&nbsp;</span>
      <div class="intel-conf none" id="iconf-hw"></div>
    </div>
    <div class="intel-cell" id="ic-locale">
      <span class="intel-label">locale / tz</span>
      <span class="intel-value" id="iv-locale">—</span>
      <span class="intel-sub"  id="is-locale">&nbsp;</span>
      <div class="intel-conf none" id="iconf-locale"></div>
    </div>
    <div class="intel-cell" id="ic-privacy">
      <span class="intel-label">privacy mode</span>
      <span class="intel-value" id="iv-privacy">—</span>
      <span class="intel-sub"  id="is-privacy">&nbsp;</span>
      <div class="intel-conf none" id="iconf-privacy"></div>
    </div>
  </div>

  <div id="hash-bar">
    <span class="label">Master Fingerprint:</span>
    <span id="master-hash">computing...</span>
    <button class="hash-btn" onclick="copyHash()" title="Copy master fingerprint to clipboard">⧉ copy</button>
    <button class="hash-btn" onclick="exportReport()" title="Download the full fingerprint report as JSON">⇓ export JSON</button>
    <span id="entropy-score"></span>
  </div>
  <div id="hash-bar2">
    <span class="label">Session Hash (incl. network/volatile):</span>
    <span id="session-hash">computing...</span>
  </div>
  <div id="status-bar"></div>
</div>

<!-- ── Main Container ───────────────────────────────────────────────────── -->

<div id="container">

  <!-- §0  AI Analyst Summary -->

  <div class="section" id="sec-ai">
    <div class="section-header" onclick="toggleSection('sec-ai')">
      <span class="icon">✦</span>
      <span class="title">AI Analyst Summary</span>
      <span class="count" id="cnt-ai">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body single-col" id="body-ai">
      <div class="row"><span class="row-key">AI analyst</span><span class="row-val dim">Waiting for scan to complete…</span></div>
    </div>
  </div>

  <!-- §1  System Identity -->

  <div class="section" id="sec-identity">
    <div class="section-header" onclick="toggleSection('sec-identity')">
      <span class="icon">🖥</span>
      <span class="title">System Identity</span>
      <span class="count" id="cnt-identity">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-identity"></div>
  </div>

  <!-- §2  HTTP Headers (PHP) -->

  <div class="section" id="sec-headers">
    <div class="section-header" onclick="toggleSection('sec-headers')">
      <span class="icon">🌐</span>
      <span class="title">HTTP Headers &amp; Server Variables</span>
      <span class="count" id="cnt-headers">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-headers"></div>
  </div>

  <!-- §3  Display & Screen -->

  <div class="section" id="sec-screen">
    <div class="section-header" onclick="toggleSection('sec-screen')">
      <span class="icon">📺</span>
      <span class="title">Display &amp; Screen</span>
      <span class="count" id="cnt-screen">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-screen"></div>
  </div>

  <!-- §4  Canvas Fingerprint -->

  <div class="section" id="sec-canvas">
    <div class="section-header" onclick="toggleSection('sec-canvas')">
      <span class="icon">🎨</span>
      <span class="title">Canvas 2D Fingerprint</span>
      <span class="count" id="cnt-canvas">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body single-col" id="body-canvas"></div>
  </div>

  <!-- §5  WebGL / GPU -->

  <div class="section" id="sec-webgl">
    <div class="section-header" onclick="toggleSection('sec-webgl')">
      <span class="icon">🎮</span>
      <span class="title">WebGL / GPU</span>
      <span class="count" id="cnt-webgl">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-webgl"></div>
  </div>

  <!-- §6  Audio Fingerprint -->

  <div class="section" id="sec-audio">
    <div class="section-header" onclick="toggleSection('sec-audio')">
      <span class="icon">🔊</span>
      <span class="title">Audio Fingerprint (OfflineAudioContext)</span>
      <span class="count" id="cnt-audio">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-audio"></div>
  </div>

  <!-- §7  Font Detection -->

  <div class="section collapsed" id="sec-fonts">
    <div class="section-header" onclick="toggleSection('sec-fonts')">
      <span class="icon">🔤</span>
      <span class="title">Installed Font Detection</span>
      <span class="count" id="cnt-fonts">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body single-col" id="body-fonts"></div>
  </div>

  <!-- §8  Locale & Timezone -->

  <div class="section" id="sec-locale">
    <div class="section-header" onclick="toggleSection('sec-locale')">
      <span class="icon">🌍</span>
      <span class="title">Locale, Timezone &amp; Internationalization</span>
      <span class="count" id="cnt-locale">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-locale"></div>
  </div>

  <!-- §9  Network -->

  <div class="section" id="sec-network">
    <div class="section-header" onclick="toggleSection('sec-network')">
      <span class="icon">📡</span>
      <span class="title">Network &amp; Connectivity</span>
      <span class="count" id="cnt-network">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-network"></div>
  </div>

  <!-- §10 Battery -->

  <div class="section" id="sec-battery">
    <div class="section-header" onclick="toggleSection('sec-battery')">
      <span class="icon">🔋</span>
      <span class="title">Battery Status</span>
      <span class="count" id="cnt-battery">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-battery"></div>
  </div>

  <!-- §11 Storage & Memory -->

  <div class="section" id="sec-storage">
    <div class="section-header" onclick="toggleSection('sec-storage')">
      <span class="icon">💾</span>
      <span class="title">Storage, Memory &amp; Compute</span>
      <span class="count" id="cnt-storage">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-storage"></div>
  </div>

  <!-- §12 Media Devices -->

  <div class="section" id="sec-media">
    <div class="section-header" onclick="toggleSection('sec-media')">
      <span class="icon">🎙</span>
      <span class="title">Media Devices</span>
      <span class="count" id="cnt-media">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-media"></div>
  </div>

  <!-- §13 Speech Synthesis -->

  <div class="section collapsed" id="sec-speech">
    <div class="section-header" onclick="toggleSection('sec-speech')">
      <span class="icon">🗣</span>
      <span class="title">Speech Synthesis Voices</span>
      <span class="count" id="cnt-speech">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body single-col" id="body-speech"></div>
  </div>

  <!-- §14 Permissions -->

  <div class="section" id="sec-permissions">
    <div class="section-header" onclick="toggleSection('sec-permissions')">
      <span class="icon">🔐</span>
      <span class="title">Permissions API</span>
      <span class="count" id="cnt-permissions">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-permissions"></div>
  </div>

  <!-- §15 WebRTC -->

  <div class="section" id="sec-webrtc">
    <div class="section-header" onclick="toggleSection('sec-webrtc')">
      <span class="icon">📶</span>
      <span class="title">WebRTC Local IP Enumeration</span>
      <span class="count" id="cnt-webrtc">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-webrtc"></div>
  </div>

  <!-- §16 CSS Media Features -->

  <div class="section" id="sec-css">
    <div class="section-header" onclick="toggleSection('sec-css')">
      <span class="icon">🎛</span>
      <span class="title">CSS Media Features</span>
      <span class="count" id="cnt-css">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-css"></div>
  </div>

  <!-- §17 Feature Detection -->

  <div class="section" id="sec-features">
    <div class="section-header" onclick="toggleSection('sec-features')">
      <span class="icon">🧪</span>
      <span class="title">API &amp; Feature Detection Matrix</span>
      <span class="count" id="cnt-features">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-features"></div>
  </div>

  <!-- §18 Math / FPU -->

  <div class="section collapsed" id="sec-math">
    <div class="section-header" onclick="toggleSection('sec-math')">
      <span class="icon">🧮</span>
      <span class="title">Math / FPU Fingerprint</span>
      <span class="count" id="cnt-math">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-math"></div>
  </div>

  <!-- §19 Performance -->

  <div class="section" id="sec-perf">
    <div class="section-header" onclick="toggleSection('sec-perf')">
      <span class="icon">⚡</span>
      <span class="title">Performance &amp; Timing</span>
      <span class="count" id="cnt-perf">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-perf"></div>
  </div>

  <!-- §20 Input -->

  <div class="section" id="sec-input">
    <div class="section-header" onclick="toggleSection('sec-input')">
      <span class="icon">🖱</span>
      <span class="title">Input Capabilities</span>
      <span class="count" id="cnt-input">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-input"></div>
  </div>

  <!-- §21 PHP Server Raw -->

  <div class="section collapsed" id="sec-php">
    <div class="section-header" onclick="toggleSection('sec-php')">
      <span class="icon">🔧</span>
      <span class="title">PHP $_SERVER Raw Dump</span>
      <span class="count" id="cnt-php">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body single-col" id="body-php"></div>
  </div>

  <!-- §22 WebKit / Safari / Apple -->

  <div class="section collapsed" id="sec-webkit">
    <div class="section-header" onclick="toggleSection('sec-webkit')">
      <span class="icon">🍎</span>
      <span class="title">WebKit / Safari / Apple Platform</span>
      <span class="count" id="cnt-webkit">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-webkit"></div>
  </div>

  <!-- §23 Microsoft Edge -->

  <div class="section collapsed" id="sec-edge">
    <div class="section-header" onclick="toggleSection('sec-edge')">
      <span class="icon">🔷</span>
      <span class="title">Microsoft Edge / Chromium-Specific</span>
      <span class="count" id="cnt-edge">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-edge"></div>
  </div>

  <!-- §24 Firefox / Gecko -->

  <div class="section collapsed" id="sec-firefox">
    <div class="section-header" onclick="toggleSection('sec-firefox')">
      <span class="icon">🦊</span>
      <span class="title">Firefox / Gecko-Specific</span>
      <span class="count" id="cnt-firefox">—</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div class="section-body" id="body-firefox"></div>
  </div>

</div><!-- /container -->

<script>
// Server-side payload — injected by PHP before the application script below.
const PHP_DATA = <?php echo $php_payload; ?> || {};
</script>
<script>
"use strict";function e(e){let t=2166136261;for(let n=0;n<e.length;n++)t^=e.charCodeAt(n),t=16777619*t>>>0;return("00000000"+t.toString(16)).slice(-8).toUpperCase()}function t(e){let t=-559038737;for(let n=0;n<e.length;n++){let o=e.charCodeAt(n);o=Math.imul(o^o>>>16,73244475),o=Math.imul(o^o>>>16,73244475),o^=o>>>16,t^=o,t=Math.imul(t,33)+o|0}return("00000000"+(t>>>0).toString(16)).slice(-8).toUpperCase()}function n(n){return e(n.join("|"))+"-"+t(n.join("~"))}function o(e,t,n){const o=document.getElementById(e);o.innerHTML="",t.forEach(([e,t,n])=>{const i=document.createElement("div");i.className="row";const r=document.createElement("span");r.className="row-key",r.textContent=e;const a=document.createElement("span");a.className="row-val"+(n?" "+n:""),a.innerHTML=t,i.appendChild(r),i.appendChild(a),o.appendChild(i)}),n&&(document.getElementById(n).textContent=t.length)}function i(e,t,n,o){const i=document.getElementById(e),r=document.createElement("div");r.className="row";const a=document.createElement("span");a.className="row-key",a.textContent=t;const s=document.createElement("span");s.className="row-val"+(o?" "+o:""),s.innerHTML=n,r.appendChild(a),r.appendChild(s),i.appendChild(r);const c=document.getElementById(e.replace("body-","cnt-"));c&&(c.textContent=i.querySelectorAll(".row").length)}function r(e,t){return`<span class="tag ${t}">${e}</span>`}function a(e){return e?r("YES","yes"):r("NO","no")}function s(e){return String(e).replace(/[&<>"']/g,e=>({"&":"&amp;",
"<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[e]))}function c(e){try{const t=window[e],n="__bp_probe__";return t.setItem(n,"1"),t.removeItem(n),!0}catch(e){return!1}}function d(e,t){document.getElementById("status-bar").innerHTML+=`<span class="status-chip ${t}">${e}</span>`}function toggleSection(e){document.getElementById(e).classList.toggle("collapsed")}function l(e,t){document.getElementById("loader-fill").style.width=e+"%",t&&(document.getElementById("loader-msg").textContent=t)}const p={};async function u(){l(5,"Collecting system identity...");const e=navigator,t=[];if(t.push(["userAgent",s(e.userAgent),"cyan"]),t.push(["platform",e.platform||"(empty)","yellow"]),t.push(["vendor",e.vendor||"(empty)",""]),t.push(["vendorSub",e.vendorSub||"(empty)",""]),t.push(["product",e.product||"(empty)",""]),t.push(["productSub",e.productSub||"(empty)",""]),t.push(["appName",e.appName||"(empty)",""]),t.push(["appCodeName",e.appCodeName||"(empty)",""]),t.push(["appVersion",e.appVersion?s(e.appVersion.substring(0,80))+"…":"(empty)",""]),t.push(["oscpu",s(e.oscpu||"(not exposed)"),""]),t.push(["buildID",e.buildID||"(not exposed)",""]),t.push(["pdfViewerEnabled",a(e.pdfViewerEnabled),""]),t.push(["cookieEnabled",a(e.cookieEnabled),""]),t.push(["doNotTrack",e.doNotTrack??"(not set)","1"===e.doNotTrack?"yellow":""]),t.push(["globalPrivacyControl",null!=e.globalPrivacyControl?String(e.globalPrivacyControl):"(not set)",""]),t.push(["webdriver",a(e.webdriver),e.webdriver?"red":""]),
t.push(["onLine",a(e.onLine),""]),t.push(["hardwareConcurrency",String(e.hardwareConcurrency||0),"green"]),t.push(["deviceMemory (GB)",null!=e.deviceMemory?e.deviceMemory+" GB":"(not exposed)","green"]),t.push(["maxTouchPoints",String(e.maxTouchPoints||0),""]),t.push(["language",e.language||"—",""]),t.push(["languages",(e.languages||[]).join(", ")||"—",""]),t.push(["plugins count",String((e.plugins||{length:0}).length),""]),e.plugins&&e.plugins.length){const n=Array.from(e.plugins).map(e=>s(e.name)).join("<br>");t.push(["plugins list",n,"dim"])}if(t.push(["mimeTypes count",String((e.mimeTypes||{length:0}).length),""]),e.keyboard)try{const n=await e.keyboard.getLayoutMap();t.push(["keyboard layout entries",String(n.size),"cyan"]);const o=[];n.forEach((e,t)=>o.push(t+"→"+e)),t.push(["keyboard sample (first 10)",o.slice(0,10).join(", "),"dim"])}catch(e){t.push(["keyboard layout","(access denied: "+e.message+")","dim"])}else t.push(["keyboard API","(not available)","dim"]);if(e.userAgentData){const n=e.userAgentData;t.push(["UAData.platform",n.platform||"—","purple"]),t.push(["UAData.mobile",a(n.mobile),""]);const o=(n.brands||[]).map(e=>s(e.brand+"@"+e.version)).join(", ");t.push(["UAData.brands",o||"—","purple"]);try{const e=await n.getHighEntropyValues(["architecture","bitness","model","platform","platformVersion","uaFullVersion","fullVersionList","wow64"]);t.push(["CH: architecture",e.architecture||"—","purple"]),t.push(["CH: bitness",e.bitness||"—","purple"]),
t.push(["CH: model",e.model||"—","purple"]),t.push(["CH: platform",e.platform||"—","purple"]),t.push(["CH: platformVersion",e.platformVersion||"—","purple"]),t.push(["CH: uaFullVersion",e.uaFullVersion||"—","purple"]),t.push(["CH: wow64",null!=e.wow64?String(e.wow64):"—","purple"]);const o=(e.fullVersionList||[]).map(e=>s(e.brand+"@"+e.version)).join(", ");t.push(["CH: fullVersionList",o||"—","purple"]),p.uaCH=JSON.stringify(e)}catch(e){t.push(["UA-CH getHighEntropyValues","(failed: "+e.message+")","red"])}}else t.push(["UA-CH API","(not available — not Chromium?)","dim"]);p.userAgent=e.userAgent,p.platform=e.platform||"",p.languages=(e.languages||[]).join(","),p.hw_concurrency=String(e.hardwareConcurrency||0),p.device_memory=String(e.deviceMemory||"?"),o("body-identity",t,"cnt-identity")}function h(){l(12,"Parsing HTTP headers...");const e=[],t=PHP_DATA.headers||{};Object.entries(t).forEach(([t,n])=>e.push([s(t),s(String(n)),""]));const n=PHP_DATA.server||{};["REMOTE_ADDR","HTTP_X_FORWARDED_FOR","HTTP_X_REAL_IP","SERVER_PROTOCOL","SERVER_SOFTWARE","REQUEST_METHOD","REQUEST_URI","HTTP_HOST","HTTPS","SERVER_PORT","GATEWAY_INTERFACE","PHP_SELF"].forEach(t=>{n[t]&&e.push(["[SERVER] "+s(t),s(String(n[t])),"yellow"])}),e.push(["PHP version",PHP_DATA.php_version,"green"]),e.push(["PHP OS",PHP_DATA.php_os,""]),e.push(["PHP SAPI",PHP_DATA.php_sapi,""]),e.push(["PHP INT_SIZE",String(PHP_DATA.php_int_size)+"B ("+8*PHP_DATA.php_int_size+"-bit)",""]),
e.push(["Collection time (UTC)",PHP_DATA.timestamp_utc,"dim"]),p.remoteAddr=PHP_DATA.remote_addr||"",p.forwardedFor=PHP_DATA.forwarded_for||"",o("body-headers",e,"cnt-headers")}function m(){l(20,"Measuring display geometry...");const e=screen,t=[["screen.width",e.width+" px","cyan"],["screen.height",e.height+" px","cyan"],["screen.availWidth",e.availWidth+" px",""],["screen.availHeight",e.availHeight+" px",""],["screen.availLeft",("number"==typeof e.availLeft?e.availLeft:0)+" px",""],["screen.availTop",("number"==typeof e.availTop?e.availTop:0)+" px",""],["screen.colorDepth",e.colorDepth+" bits","green"],["screen.pixelDepth",e.pixelDepth+" bits",""],["window.devicePixelRatio",String(window.devicePixelRatio),"yellow"],["window.innerWidth",window.innerWidth+" px",""],["window.innerHeight",window.innerHeight+" px",""],["window.outerWidth",window.outerWidth+" px",""],["window.outerHeight",window.outerHeight+" px",""],["window.screenX",window.screenX+" px",""],["window.screenY",window.screenY+" px",""],["window.scrollX",window.scrollX+" px",""],["window.scrollY",window.scrollY+" px",""],["document.visibilityState",document.visibilityState,""]];e.orientation&&(t.push(["screen.orientation.type",e.orientation.type,""]),t.push(["screen.orientation.angle",e.orientation.angle+"°",""]));let n="unknown";[72,96,120,144,192,240,300,360].forEach(e=>{window.matchMedia(`(min-resolution: ${e}dpi)`).matches&&(n=">= "+e)}),t.push(["Approx. screen DPI",n,"yellow"])
;const i=Math.round(e.width/window.devicePixelRatio),r=Math.round(e.height/window.devicePixelRatio);t.push(["Logical resolution",i+" × "+r+" (CSS px)",""]),p.screen=`${e.width}x${e.height}x${e.colorDepth}@${window.devicePixelRatio}`,o("body-screen",t,"cnt-screen")}function g(){l(28,"Rendering canvas fingerprint...");const n=document.getElementById("body-canvas");n.innerHTML="";const o=document.createElement("div");o.id="canvas-preview-wrap";const i=document.createElement("canvas");i.width=400,i.height=120;const r=i.getContext("2d");r.fillStyle="#1a1a2e",r.fillRect(0,0,400,120);const a=r.createLinearGradient(0,0,400,0);a.addColorStop(0,"#39d353"),a.addColorStop(.5,"#58d4f0"),a.addColorStop(1,"#bc8cff"),r.fillStyle=a,r.font="bold 18px Arial, sans-serif",r.fillText("BrowserPrint FP Canvas Test",12,30),r.font="14px Georgia, serif",r.fillStyle="#e3b341",r.fillText("Ω ℕ ∆ π ∑ √ ≈ ≠ • ← → ↑ ↓ ★ ♠ ♣ ♥ ♦",12,55),r.font="italic 12px Times New Roman, serif",r.fillStyle="#c9d1d9",r.fillText("The quick brown fox jumps over the lazy dog. 0123456789",12,75),r.fillStyle="rgba(88,212,240,0.5)",r.beginPath(),r.arc(360,60,25,0,2*Math.PI),r.fill(),r.fillStyle="rgba(188,140,255,0.4)",r.fillRect(310,30,35,55),r.strokeStyle="#f85149",r.lineWidth=2,r.beginPath(),r.moveTo(290,20),r.lineTo(380,100),r.stroke(),r.font="11.3px Arial",r.fillStyle="#ffffff",r.fillText("Subpixel: 1.33 2.67 3.14",12,100),r.shadowColor="rgba(57,211,83,0.8)",r.shadowBlur=8,r.fillStyle="#39d353",r.fillText("SHADOW",12,115),
r.shadowBlur=0;const s=i.toDataURL("image/png"),c=e(s)+"-"+t(s),d=document.createElement("div");d.innerHTML=`\n    <div class="row"><span class="row-key">Canvas hash (FNV32a+MH3)</span><span class="row-val cyan">${c}</span></div>\n    <div class="row"><span class="row-key">dataURL length</span><span class="row-val">${s.length} chars</span></div>\n    <div class="row"><span class="row-key">toDataURL format</span><span class="row-val">image/png</span></div>\n  `,o.appendChild(i),o.appendChild(d),n.appendChild(o);const u=i.toDataURL("image/jpeg",.9),h=e(u),m=document.createElement("div");m.className="row",m.innerHTML=`<span class="row-key">JPEG hash (q=0.9)</span><span class="row-val cyan">${h}</span>`,n.appendChild(m);const g=document.createElement("div");g.className="row",g.innerHTML=`<span class="row-key">JPEG dataURL length</span><span class="row-val">${u.length} chars</span>`,n.appendChild(g);const f=r.getImageData(0,0,10,1),v=Array.from(f.data).slice(0,40).map(e=>e.toString(16).padStart(2,"0")).join(" "),y=document.createElement("div");y.className="row",y.innerHTML=`<span class="row-key">Pixel sample [0,0..9,0] RGBA</span><span class="row-val dim" style="font-size:10px">${v}</span>`,n.appendChild(y),document.getElementById("cnt-canvas").textContent=String(n.querySelectorAll(".row").length),p.canvas=c}function f(){l(36,"Probing WebGL/GPU surface...");const t=[];function n(e){return document.createElement("canvas").getContext(e,{failIfMajorPerformanceCaveat:!1})||null}
const r=n("webgl")||n("experimental-webgl");if(r){t.push(["WebGL1","Available","green"]);const n=r.getExtension("WEBGL_debug_renderer_info");if(n){const e=r.getParameter(n.UNMASKED_RENDERER_WEBGL),o=r.getParameter(n.UNMASKED_VENDOR_WEBGL);t.push(["GPU Renderer (unmasked)",s(e),"yellow"]),t.push(["GPU Vendor (unmasked)",s(o),"yellow"]),p.gpuRenderer=e,p.gpuVendor=o}t.push(["RENDERER",s(r.getParameter(r.RENDERER)),""]),t.push(["VENDOR",s(r.getParameter(r.VENDOR)),""]),t.push(["VERSION",s(r.getParameter(r.VERSION)),"cyan"]),t.push(["SHADING_LANGUAGE_VER",s(r.getParameter(r.SHADING_LANGUAGE_VERSION)),""]),t.push(["MAX_TEXTURE_SIZE",r.getParameter(r.MAX_TEXTURE_SIZE)+" px",""]),t.push(["MAX_VIEWPORT_DIMS",r.getParameter(r.MAX_VIEWPORT_DIMS).join(" × ")+" px",""]),t.push(["MAX_VERTEX_ATTRIBS",String(r.getParameter(r.MAX_VERTEX_ATTRIBS)),""]),t.push(["MAX_VERTEX_TEXTURE_IMAGE_UNITS",String(r.getParameter(r.MAX_VERTEX_TEXTURE_IMAGE_UNITS)),""]),t.push(["MAX_FRAGMENT_UNIFORM_VECTORS",String(r.getParameter(r.MAX_FRAGMENT_UNIFORM_VECTORS)),""]),t.push(["MAX_VERTEX_UNIFORM_VECTORS",String(r.getParameter(r.MAX_VERTEX_UNIFORM_VECTORS)),""]),t.push(["MAX_RENDERBUFFER_SIZE",String(r.getParameter(r.MAX_RENDERBUFFER_SIZE)),""]),t.push(["ALPHA_BITS",String(r.getParameter(r.ALPHA_BITS)),""]),t.push(["DEPTH_BITS",String(r.getParameter(r.DEPTH_BITS)),""]),t.push(["STENCIL_BITS",String(r.getParameter(r.STENCIL_BITS)),""]),t.push(["ANTIALIAS",String(r.getContextAttributes()?.antialias),""])
;const o=r.getShaderPrecisionFormat(r.FRAGMENT_SHADER,r.HIGH_FLOAT);o&&t.push(["FRAGMENT HIGH_FLOAT precision",`range:${o.rangeMin}..${o.rangeMax} precision:${o.precision}`,""]);const i=r.getSupportedExtensions()||[];t.push(["WebGL1 extensions count",String(i.length),"green"]),t.push(["WebGL1 extensions",i.map(e=>`<span class="tag item">${s(e)}</span>`).join(""),""]),p.webgl1ExtCount=String(i.length);const a=document.createElement("canvas");a.width=256,a.height=256;const c=a.getContext("webgl")||a.getContext("experimental-webgl");if(c){const n="attribute vec2 p;void main(){gl_Position=vec4(p,0.0,1.0);}",o="precision mediump float;void main(){gl_FragColor=vec4(0.3,0.8,0.2,1.0);}",i=c.createShader(c.VERTEX_SHADER);c.shaderSource(i,n),c.compileShader(i);const r=c.createShader(c.FRAGMENT_SHADER);c.shaderSource(r,o),c.compileShader(r);const a=c.createProgram();c.attachShader(a,i),c.attachShader(a,r),c.linkProgram(a),c.useProgram(a);const s=c.createBuffer();c.bindBuffer(c.ARRAY_BUFFER,s),c.bufferData(c.ARRAY_BUFFER,new Float32Array([-.5,-.5,.5,-.5,0,.5]),c.STATIC_DRAW);const d=c.getAttribLocation(a,"p");c.enableVertexAttribArray(d),c.vertexAttribPointer(d,2,c.FLOAT,!1,0,0),c.clearColor(0,0,0,1),c.clear(c.COLOR_BUFFER_BIT),c.drawArrays(c.TRIANGLES,0,3);const l=new Uint8Array(c.drawingBufferWidth*c.drawingBufferHeight*4);c.readPixels(0,0,c.drawingBufferWidth,c.drawingBufferHeight,c.RGBA,c.UNSIGNED_BYTE,l);const u=e(Array.from(l.slice(0,256)).join(","))
;t.push(["WebGL render hash",u,"cyan"]),p.webglRender=u}}else t.push(["WebGL1","NOT available","red"]);const a=n("webgl2");if(a){t.push(["WebGL2","Available","green"]),t.push(["WebGL2 VERSION",s(a.getParameter(a.VERSION)),"cyan"]),t.push(["MAX_3D_TEXTURE_SIZE",String(a.getParameter(a.MAX_3D_TEXTURE_SIZE)),""]),t.push(["MAX_DRAW_BUFFERS",String(a.getParameter(a.MAX_DRAW_BUFFERS)),""]),t.push(["MAX_SAMPLES",String(a.getParameter(a.MAX_SAMPLES)),""]);const e=a.getSupportedExtensions()||[];t.push(["WebGL2 extensions count",String(e.length),""])}else t.push(["WebGL2","NOT available","warn"]);navigator.gpu?(t.push(["WebGPU API","Present (navigator.gpu exists)","green"]),navigator.gpu.requestAdapter().then(e=>{if(e){const t=e.info||{};i("body-webgl","WebGPU adapter.vendor",t.vendor||"(not exposed)","purple"),i("body-webgl","WebGPU adapter.architecture",t.architecture||"(not exposed)","purple"),i("body-webgl","WebGPU adapter.device",t.device||"(not exposed)","purple"),i("body-webgl","WebGPU adapter.description",t.description||"(not exposed)","purple")}else i("body-webgl","WebGPU adapter","(null — no capable adapter)","dim")}).catch(()=>{})):t.push(["WebGPU API","NOT available","dim"]),o("body-webgl",t,"cnt-webgl")}function v(){return l(44,"Computing audio fingerprint..."),new Promise(n=>{const i=[];try{const r=window.OfflineAudioContext||window.webkitOfflineAudioContext;if(!r)throw new Error("OfflineAudioContext not available");const a=new r(1,4096,44100),s=a.createOscillator()
;s.type="triangle",s.frequency.setValueAtTime(1e4,a.currentTime);const c=a.createDynamicsCompressor();c.threshold.setValueAtTime(-50,a.currentTime),c.knee.setValueAtTime(40,a.currentTime),c.ratio.setValueAtTime(12,a.currentTime),c.attack.setValueAtTime(0,a.currentTime),c.release.setValueAtTime(.25,a.currentTime);const d=a.createBiquadFilter();d.type="highpass",d.frequency.setValueAtTime(500,a.currentTime),s.connect(c),c.connect(d),d.connect(a.destination),s.start(0),a.startRendering().then(r=>{const s=r.getChannelData(0);let c=0,d=0;const l=[];for(let e=0;e<s.length;e++){const t=Math.abs(s[e]);c+=t,t>d&&(d=t),e<32&&l.push(s[e].toFixed(10))}const u=c/s.length,h=l.join(","),m=e(h)+"-"+t(h);i.push(["Audio hash (FNV32a+MH3)",m,"cyan"]),i.push(["Sample rate",String(r.sampleRate)+" Hz",""]),i.push(["Buffer length",String(r.length)+" frames",""]),i.push(["Channels",String(r.numberOfChannels),""]),i.push(["Peak amplitude",d.toFixed(12),"yellow"]),i.push(["Average amplitude",u.toFixed(12),""]),i.push(["First 8 samples",l.slice(0,8).join(", "),"dim"]),i.push(["sampleRate",String(a.sampleRate),""]),i.push(["baseLatency",null!=a.baseLatency?a.baseLatency.toFixed(6)+"s":"(N/A)",""]),p.audio=m,o("body-audio",i,"cnt-audio"),n()}).catch(e=>{i.push(["Audio render error",e.message,"red"]),o("body-audio",i,"cnt-audio"),n()})}catch(e){i.push(["Audio fingerprint","FAILED: "+e.message,"red"]),o("body-audio",i,"cnt-audio"),n()}})}function y(){l(52,"Enumerating installed fonts...")
;const t=["monospace","serif","sans-serif"],n=document.createElement("canvas");n.width=400,n.height=120;const o=n.getContext("2d");function i(e,t){return o.font="72px "+e+", "+t,o.measureText("mmmmmmmmmmlli").width}const a={};t.forEach(e=>{a[e]=i(e,e)})
;const s=[...new Set(["Arial","Arial Black","Arial Narrow","Arial Rounded MT Bold","Bahnschrift","Calibri","Cambria","Cambria Math","Candara","Comic Sans MS","Consolas","Constantia","Corbel","Courier New","Ebrima","Franklin Gothic Medium","Gabriola","Gadugi","Georgia","HoloLens MDL2 Assets","Impact","Ink Free","Javanese Text","Leelawadee UI","Lucida Console","Lucida Sans Unicode","Malgun Gothic","Marlett","Microsoft Himalaya","Microsoft JhengHei","Microsoft New Tai Lue","Microsoft PhagsPa","Microsoft Sans Serif","Microsoft Tai Le","Microsoft Uighur","Microsoft YaHei","Microsoft Yi Baiti","MingLiU-ExtB","Mongolian Baiti","MS Gothic","MS PGothic","MS UI Gothic","MV Boli","Myanmar Text","Nirmala UI","Palatino Linotype","Segoe MDL2 Assets","Segoe Print","Segoe Script","Segoe UI","Segoe UI Black","Segoe UI Emoji","Segoe UI Historic","Segoe UI Symbol","SimSun","Sitka","Sylfaen","Symbol","Tahoma","Times New Roman","Trebuchet MS","Verdana","Webdings","Wingdings","Yu Gothic","American Typewriter","Andale Mono","Apple Braille","Apple Chancery","Apple Color Emoji","Apple SD Gothic Neo","Apple Symbols","AppleGothic","AppleMyungjo","Arial Hebrew","Avenir","Avenir Next","Avenir Next Condensed","Baskerville","Big Caslon","Bodoni 72","Bodoni 72 Oldstyle","Bodoni 72 Smallcaps","Bradley Hand","Chalkboard","Chalkboard SE","Chalkduster","Charter","Cochin","Copperplate","Courier","Damascus","DecoType Naskh","Diwan Mishafi","Euphemia UCAS","Farah","Futura","Geneva","Gill Sans","Helvetica","Helvetica Neue","Herculanum","Hoefler Text","Kefa","Khmer Sangam MN","Kohinoor Bangla","Marker Felt","Menlo","Monaco","Mshtakan","Mukta Mahee","Muna","Myanmar Sangam MN","Nadeem","New Peninim MT","Noteworthy","Optima","Osaka","Palatino","Papyrus","Phosphate","PingFang SC","PT Mono","PT Sans","PT Serif",
"Rockwell","Savoye LET","Sinhala Sangam MN","Skia","Snell Roundhand","Songti SC","STHeiti","STIXGeneral","STIXSizeFiveSym","STIXSizeFourSym","STIXSizeOneSym","STIXSizeThreeSym","STIXSizeTwoSym","STIXVariants","Symbol","Tamil Sangam MN","Thonburi","Times","Trattatello","Zapf Dingbats","Zapfino","Cantarell","DejaVu Sans","DejaVu Sans Mono","DejaVu Serif","Droid Sans","Droid Sans Mono","Droid Serif","FreeMono","FreeSans","FreeSerif","Liberation Mono","Liberation Sans","Liberation Serif","Nimbus Mono PS","Nimbus Roman","Nimbus Sans","Noto Mono","Noto Sans","Noto Serif","Ubuntu","Ubuntu Condensed","Ubuntu Mono","Roboto","Open Sans","Lato","Oswald","Source Sans Pro","Montserrat","Raleway","PT Sans","Merriweather","Nunito","Playfair Display","Poppins","Fira Code","JetBrains Mono","Inter","Wingdings 2","Wingdings 3","Webdings","MS Mincho","DFKai-SB","BIZ UDGothic","BIZ UDMincho","Noto Color Emoji"])],c=[]
;s.forEach(e=>{t.some(t=>i(e,t)!==a[t])&&c.push(e)});const d=document.getElementById("body-fonts");d.innerHTML="";const u=document.createElement("div");u.className="row",u.innerHTML=`<span class="row-key">Fonts tested (unique, ×3 baselines)</span><span class="row-val">${s.length}</span>`,d.appendChild(u);const h=document.createElement("div");h.className="row",h.innerHTML=`<span class="row-key">Fonts detected</span><span class="row-val green">${c.length}</span>`,d.appendChild(h);const m=document.createElement("div");m.id="font-grid",c.forEach(e=>{m.innerHTML+=r(e,"item")}),d.appendChild(m),document.getElementById("cnt-fonts").textContent=c.length+" / "+s.length,p.fonts=e(c.join(","))}function w(){l(60,"Reading locale and timezone...");const e=Intl.DateTimeFormat().resolvedOptions(),t=e.timeZone,n=-(new Date).getTimezoneOffset(),i=[["Timezone (IANA)",t,"yellow"],["UTC offset",`UTC${n>=0?"+":""}${Math.floor(n/60)}:${String(Math.abs(n%60)).padStart(2,"0")}`,""],["Raw offset (minutes)",String(n),""],["DTF locale",e.locale,"cyan"],["DTF calendar",e.calendar,""],["DTF numberingSystem",e.numberingSystem,""],["navigator.language",navigator.language,""],["navigator.languages",(navigator.languages||[]).join(", "),""],["Current local time",(new Date).toLocaleString(),""],["ISO timestamp",(new Date).toISOString(),"dim"]];try{const e=(new Intl.NumberFormat).resolvedOptions();i.push(["Number locale",e.locale,""]),i.push(["Number numberingSystem",e.numberingSystem,""])}catch(e){}try{
const e=(new Intl.Collator).resolvedOptions();i.push(["Collator locale",e.locale,""]),i.push(["Collator usage",e.usage,""]),i.push(["Collator caseFirst",e.caseFirst,""])}catch(e){}if(Intl.supportedValuesOf)try{const e=Intl.supportedValuesOf("calendar");i.push(["Supported calendars",String(e.length)+" → "+e.slice(0,5).join(", ")+"…","dim"]);const t=Intl.supportedValuesOf("timeZone");i.push(["Supported timezones",String(t.length),"dim"])}catch(e){}p.timezone=t,p.locale=navigator.language,o("body-locale",i,"cnt-locale")}function S(){l(63,"Probing network info...");const e=navigator.connection||navigator.mozConnection||navigator.webkitConnection,t=[["navigator.onLine",a(navigator.onLine),""]];e?(t.push(["effectiveType",e.effectiveType||"—","cyan"]),t.push(["type",e.type||"(not exposed)",""]),t.push(["downlink (Mbps)",null!=e.downlink?e.downlink+" Mbps":"—","green"]),t.push(["downlinkMax (Mbps)",null!=e.downlinkMax?e.downlinkMax+" Mbps":"—",""]),t.push(["rtt (ms)",null!=e.rtt?e.rtt+" ms":"—","yellow"]),t.push(["saveData",a(e.saveData),""])):t.push(["Network Information API","(not available)","dim"]),t.push(["PHP REMOTE_ADDR",s(PHP_DATA.remote_addr||"—"),"yellow"]),t.push(["X-Forwarded-For",s(PHP_DATA.forwarded_for||"(none)"),""]),t.push(["X-Real-IP",s(PHP_DATA.real_ip||"(none)"),""]),t.push(["Server protocol",PHP_DATA.server_protocol||"—",""]),o("body-network",t,"cnt-network")}function b(){l(66,"Querying battery status...");const e=[]
;return navigator.getBattery?navigator.getBattery().then(t=>{e.push(["charging",a(t.charging),""]),e.push(["level",(100*t.level).toFixed(1)+"%",t.level>.5?"green":t.level>.2?"yellow":"red"]),e.push(["chargingTime",t.chargingTime===1/0?"∞ (not charging)":t.chargingTime+"s",""]),e.push(["dischargingTime",t.dischargingTime===1/0?"∞ (charging or N/A)":t.dischargingTime+"s",""]),p.battery=`${t.charging?1:0}:${t.level}`,o("body-battery",e,"cnt-battery"),d("🔋 "+(100*t.level).toFixed(0)+"%",t.level>.5?"ok":"warn")}).catch(t=>{e.push(["Battery API error",t.message,"red"]),o("body-battery",e,"cnt-battery")}):(e.push(["Battery API","NOT available","dim"]),o("body-battery",e,"cnt-battery"),Promise.resolve())}function P(){l(69,"Measuring storage and memory...");const e=[];e.push(["localStorage",a(c("localStorage")),""]),e.push(["sessionStorage",a(c("sessionStorage")),""]),e.push(["indexedDB",a("undefined"!=typeof indexedDB),""]),e.push(["caches (Cache API)",a("caches"in window),""]),e.push(["cookieStore",a("cookieStore"in window),""]);const t=performance.memory;t?(e.push(["jsHeapSizeLimit",(t.jsHeapSizeLimit/1048576).toFixed(1)+" MB","cyan"]),e.push(["totalJSHeapSize",(t.totalJSHeapSize/1048576).toFixed(1)+" MB",""]),e.push(["usedJSHeapSize",(t.usedJSHeapSize/1048576).toFixed(1)+" MB","green"])):e.push(["JS heap memory","(not exposed — non-Chromium?)","dim"]),e.push(["hardwareConcurrency",String(navigator.hardwareConcurrency||0)+" logical cores","green"]),
e.push(["deviceMemory",null!=navigator.deviceMemory?navigator.deviceMemory+" GB":"(not exposed)",""]),e.push(["WebAssembly",a("undefined"!=typeof WebAssembly),""]),"undefined"!=typeof WebAssembly&&(e.push(["WASM streaming compile",a("function"==typeof WebAssembly.compileStreaming),""]),e.push(["WASM SIMD (feature test)",(()=>{try{return WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,123,3,2,1,0,10,10,1,8,0,65,0,253,15,253,98,11]))?r("SUPPORTED","yes"):r("NO","no")}catch(e){return r("NO","no")}})(),""]),e.push(["SharedArrayBuffer",a("undefined"!=typeof SharedArrayBuffer),"undefined"!=typeof SharedArrayBuffer?"":"warn"])),o("body-storage",e,"cnt-storage"),navigator.storage&&navigator.storage.estimate&&navigator.storage.estimate().then(e=>{i("body-storage","storage.quota",e.quota?(e.quota/1073741824).toFixed(2)+" GB":"—","cyan"),i("body-storage","storage.usage",e.usage?(e.usage/1048576).toFixed(2)+" MB":"—",""),e.usageDetails&&Object.entries(e.usageDetails).forEach(([e,t])=>{i("body-storage","storage."+e,(t/1024).toFixed(1)+" KB","dim")})}).catch(()=>{})}function A(){l(72,"Enumerating media devices...");const e=[];return navigator.mediaDevices&&navigator.mediaDevices.enumerateDevices?navigator.mediaDevices.enumerateDevices().then(t=>{const n=t.filter(e=>"audioinput"===e.kind),i=t.filter(e=>"audiooutput"===e.kind),r=t.filter(e=>"videoinput"===e.kind);e.push(["Total devices",String(t.length),"cyan"]),e.push(["Audio inputs",String(n.length),""]),
e.push(["Audio outputs",String(i.length),""]),e.push(["Video inputs (cameras)",String(r.length),"green"]),t.forEach((t,n)=>{const o=t.label||"(label hidden — no permission)";e.push([`Device ${n+1} [${s(t.kind)}]`,`${s(o)} — deviceId:${s(t.deviceId.substring(0,16))}…`,"dim"])}),navigator.mediaCapabilities&&e.push(["MediaCapabilities API","Available","green"]),p.mediaDevices=String(t.length),o("body-media",e,"cnt-media")}).catch(t=>{e.push(["enumerateDevices error",t.message,"red"]),o("body-media",e,"cnt-media")}):(e.push(["MediaDevices API","NOT available","red"]),o("body-media",e,"cnt-media"),Promise.resolve())}function C(){l(75,"Enumerating speech voices...");const e=document.getElementById("body-speech"),t=new Promise(e=>{if(!window.speechSynthesis)return e();if(speechSynthesis.getVoices().length)return e();let t=!1;const n=()=>{t||(t=!0,e())};speechSynthesis.addEventListener("voiceschanged",n,{once:!0}),setTimeout(n,1500)});function n(){const t=window.speechSynthesis;if(!t)return e.innerHTML='<div class="row"><span class="row-key">Speech Synthesis</span><span class="row-val red">NOT available</span></div>',void(document.getElementById("cnt-speech").textContent="0");const n=t.getVoices();e.innerHTML="";const o=document.createElement("div");o.className="row",o.innerHTML=`<span class="row-key">Total voices</span><span class="row-val cyan">${n.length}</span>`,e.appendChild(o),n.forEach((t,n)=>{const o=document.createElement("div");o.className="row",
o.innerHTML=`<span class="row-key">Voice ${n+1}</span><span class="row-val dim">${s(t.name)} — ${s(t.lang)}${t.localService?" [local]":" [remote]"}${t.default?" ★":""}</span>`,e.appendChild(o)}),document.getElementById("cnt-speech").textContent=String(n.length),p.voices=String(n.length)}return window.speechSynthesis?(window.speechSynthesis.onvoiceschanged=n,n()):(e.innerHTML='<div class="row"><span class="row-key">Speech Synthesis</span><span class="row-val dim">NOT available</span></div>',document.getElementById("cnt-speech").textContent="0"),t.then(n)}async function M(){l(78,"Querying permissions API...");const e=[];if(!navigator.permissions)return e.push(["Permissions API","NOT available","dim"]),void o("body-permissions",e,"cnt-permissions");(await Promise.all(["geolocation","notifications","push","midi","camera","microphone","ambient-light-sensor","accelerometer","gyroscope","magnetometer","clipboard-read","clipboard-write","payment-handler","background-sync","persistent-storage","screen-wake-lock","nfc","idle-detection","window-management"].map(async e=>{try{return[e,(await navigator.permissions.query({name:e})).state]}catch(t){return[e,"error: "+t.message.split(" ")[0]]}}))).forEach(([t,n])=>{let o="";"granted"===n&&(o="green"),"denied"===n&&(o="red"),"prompt"===n&&(o="yellow"),e.push([t,n,o])}),o("body-permissions",e,"cnt-permissions")}function E(){l(81,"Probing WebRTC ICE candidates...")
;const e=document.getElementById("body-webrtc"),t=new Set,n=document.createElement("div");if(n.className="row",n.innerHTML='<span class="row-key">WebRTC status</span><span class="row-val dim">Collecting ICE candidates…</span>',e.appendChild(n),!window.RTCPeerConnection)return e.innerHTML='<div class="row"><span class="row-key">WebRTC</span><span class="row-val red">NOT available (RTCPeerConnection missing)</span></div>',void(document.getElementById("cnt-webrtc").textContent="0");try{const n=new RTCPeerConnection({iceServers:[]});n.createDataChannel("fp"),n.onicecandidate=o=>{if(!o||!o.candidate){n.close(),e.innerHTML="";const o=document.createElement("div");return o.className="row",o.innerHTML=`<span class="row-key">Unique IPs found</span><span class="row-val ${t.size>0?"yellow":"dim"}">${t.size}</span>`,e.appendChild(o),t.forEach(t=>{const n=document.createElement("div");n.className="row";const o=t.startsWith("192.168")||t.startsWith("10.")||t.startsWith("172.")?"yellow":"cyan";n.innerHTML=`<span class="row-key">Local IP</span><span class="row-val ${o}">${t}</span>`,e.appendChild(n)}),document.getElementById("cnt-webrtc").textContent=String(t.size),void(p.rtcIPs=Array.from(t).join(","))}const i=o.candidate.candidate.split(" ");if("host"===i[7]){const e=i[4];e&&!e.includes(".local")&&t.add(e)}},n.createOffer().then(e=>n.setLocalDescription(e)).catch(()=>{}),setTimeout(()=>{try{n.close()}catch(e){}},5e3)}catch(t){
e.innerHTML=`<div class="row"><span class="row-key">WebRTC error</span><span class="row-val red">${t.message}</span></div>`,document.getElementById("cnt-webrtc").textContent="0"}}function T(){function e(e){return window.matchMedia(e).matches}l(84,"Evaluating CSS media features...")
;const t=[["prefers-color-scheme: dark",a(e("(prefers-color-scheme:dark)")),""],["prefers-color-scheme: light",a(e("(prefers-color-scheme:light)")),""],["prefers-reduced-motion: reduce",a(e("(prefers-reduced-motion:reduce)")),""],["prefers-contrast: more",a(e("(prefers-contrast:more)")),""],["prefers-contrast: less",a(e("(prefers-contrast:less)")),""],["forced-colors: active",a(e("(forced-colors:active)")),""],["inverted-colors: inverted",a(e("(inverted-colors:inverted)")),""],["pointer: coarse",a(e("(pointer:coarse)")),""],["pointer: fine",a(e("(pointer:fine)")),""],["pointer: none",a(e("(pointer:none)")),""],["hover: hover",a(e("(hover:hover)")),""],["hover: none",a(e("(hover:none)")),""],["any-pointer: coarse",a(e("(any-pointer:coarse)")),""],["any-pointer: fine",a(e("(any-pointer:fine)")),""],["any-hover: hover",a(e("(any-hover:hover)")),""],["color-gamut: srgb",a(e("(color-gamut:srgb)")),""],["color-gamut: p3",a(e("(color-gamut:p3)")),"green"],["color-gamut: rec2020",a(e("(color-gamut:rec2020)")),""],["dynamic-range: high (HDR)",a(e("(dynamic-range:high)")),"green"],["update: fast",a(e("(update:fast)")),""],["overflow-block: scroll",a(e("(overflow-block:scroll)")),""],["orientation: landscape",a(e("(orientation:landscape)")),""],["orientation: portrait",a(e("(orientation:portrait)")),""],["prefers-reduced-data: reduce",a(e("(prefers-reduced-data:reduce)")),""],["display-mode: standalone",a(e("(display-mode:standalone)")),""],["display-mode: fullscreen",a(e("(display-mode:fullscreen)")),""],["min-resolution: 2dppx",a(e("(min-resolution:2dppx)")),"yellow"],["min-resolution: 3dppx",a(e("(min-resolution:3dppx)")),""],["CSS color p3 support",a(CSS.supports&&CSS.supports("color","color(display-p3 1 0 0)")),""],["CSS oklch support",a(CSS.supports&&CSS.supports("color",
"oklch(60% 0.2 240)")),""],["CSS container queries",a(CSS.supports&&CSS.supports("container-type","inline-size")),""],["CSS @layer support",a("undefined"!=typeof CSSLayerBlockRule),""],["CSS subgrid",a(CSS.supports&&CSS.supports("grid-template-rows","subgrid")),""],["CSS :has() selector",a(CSS.supports&&CSS.supports("selector(:has(*))")),""],["CSS nesting",a(CSS.supports&&CSS.supports("selector(a & b)")),""]]
;p.prefersColorScheme=e("(prefers-color-scheme:dark)")?"dark":"light",o("body-css",t,"cnt-css")}function x(){l(87,"Running feature detection matrix..."),window;const t=navigator,n=[["BigInt","undefined"!=typeof BigInt],["Proxy","undefined"!=typeof Proxy],["Promise","undefined"!=typeof Promise],["Symbol","undefined"!=typeof Symbol],["WeakRef","undefined"!=typeof WeakRef],["FinalizationRegistry","undefined"!=typeof FinalizationRegistry],["globalThis","undefined"!=typeof globalThis],["structuredClone","undefined"!=typeof structuredClone],["Error.cause",void 0!==Error({cause:0
}).cause],["Array.at()","function"==typeof[].at],["Object.hasOwn()","function"==typeof Object.hasOwn],["String.replaceAll()","function"==typeof"".replaceAll],["queueMicrotask","function"==typeof queueMicrotask],["AbortController","undefined"!=typeof AbortController],["Fetch API","undefined"!=typeof fetch],["Service Worker","serviceWorker"in t],["Web Workers","undefined"!=typeof Worker],["WebSocket","undefined"!=typeof WebSocket],["WebAssembly","undefined"!=typeof WebAssembly],["SharedArrayBuffer","undefined"!=typeof SharedArrayBuffer],["Atomics","undefined"!=typeof Atomics],["Broadcast Channel","undefined"!=typeof BroadcastChannel],["MessageChannel","undefined"!=typeof MessageChannel],["ReadableStream","undefined"!=typeof ReadableStream],["WritableStream","undefined"!=typeof WritableStream],["TransformStream","undefined"!=typeof TransformStream],["CompressionStream","undefined"!=typeof CompressionStream],["IntersectionObserver","undefined"!=typeof IntersectionObserver],["ResizeObserver","undefined"!=typeof ResizeObserver],["MutationObserver","undefined"!=typeof MutationObserver],["PerformanceObserver","undefined"!=typeof PerformanceObserver],["ReportingObserver",void 0!==window.ReportingObserver],["Web Crypto API","undefined"!=typeof crypto&&!!crypto.subtle],["crypto.randomUUID()","undefined"!=typeof crypto&&"function"==typeof crypto.randomUUID],["localStorage",c("localStorage")],["sessionStorage",c("sessionStorage")],["indexedDB","undefined"!=typeof indexedDB],["Cache API","undefined"!=typeof caches],["File System Access API",void 0!==window.showOpenFilePicker],["MediaDevices",!!t.mediaDevices],["Screen Capture API",!(!t.mediaDevices||!t.mediaDevices.getDisplayMedia)],["Picture-in-Picture",void 0!==document.pictureInPictureEnabled],["Web Audio API",
"undefined"!=typeof AudioContext||void 0!==window.webkitAudioContext],["Speech Recognition",void 0!==window.SpeechRecognition||void 0!==window.webkitSpeechRecognition],["Speech Synthesis","undefined"!=typeof speechSynthesis],["Pointer Events","undefined"!=typeof PointerEvent],["Touch Events","undefined"!=typeof TouchEvent],["Gamepad API","function"==typeof navigator.getGamepads],["DeviceOrientation","undefined"!=typeof DeviceOrientationEvent],["DeviceMotion","undefined"!=typeof DeviceMotionEvent],["Ambient Light Sensor",void 0!==window.AmbientLightSensor],["Accelerometer",void 0!==window.Accelerometer],["Gyroscope",void 0!==window.Gyroscope],["Magnetometer",void 0!==window.Magnetometer],["WebRTC","undefined"!=typeof RTCPeerConnection],["Navigator.connection",!!navigator.connection],["Background Sync",void 0!==window.SyncManager],["Push API",void 0!==window.PushManager],["Notifications API","undefined"!=typeof Notification],["Web Share API","function"==typeof navigator.share],["Clipboard API",!!navigator.clipboard],["WebGPU",!!navigator.gpu],["Screen Wake Lock",void 0!==navigator.wakeLock],["Window Controls Overlay",!!navigator.windowControlsOverlay],["View Transition API","function"==typeof document.startViewTransition],["Popover API","function"==typeof document.createElement("div").showPopover],["CSS Houdini Paint",void 0!==CSS.paintWorklet],["Payment Request API","undefined"!=typeof PaymentRequest],["Credential Mgmt API",!!navigator.credentials],["FedCM API",void 0!==window.IdentityCredential],["Web NFC",void 0!==window.NDEFReader],["Web USB",!!navigator.usb],["Web Serial",!!navigator.serial],["Web Bluetooth",!!navigator.bluetooth],["WebHID",!!navigator.hid],["WebMIDI","function"==typeof navigator.requestMIDIAccess],["Eye Dropper",void 0!==window.EyeDropper],
["Idle Detection",void 0!==window.IdleDetector],["Local Font Access",void 0!==navigator.fonts]],o=document.getElementById("body-features")
;o.innerHTML="",n.forEach(([e,t])=>{const n=document.createElement("div");n.className="row",n.innerHTML=`<span class="row-key">${e}</span><span class="row-val">${a(!!t)}</span>`,o.appendChild(n)}),document.getElementById("cnt-features").textContent=n.length+" APIs",p.featHash=e(n.map(([,e])=>e?1:0).join(""))}function I(){l(90,"Computing FPU fingerprint...");const t=[["Math.PI",Math.PI],["Math.E",Math.E],["Math.sqrt(2)",Math.sqrt(2)],["Math.sin(1)",Math.sin(1)],["Math.cos(1)",Math.cos(1)],["Math.tan(1)",Math.tan(1)],["Math.asin(0.5)",Math.asin(.5)],["Math.acos(0.5)",Math.acos(.5)],["Math.atan(1)",Math.atan(1)],["Math.atan2(1,2)",Math.atan2(1,2)],["Math.exp(1)",Math.exp(1)],["Math.log(2)",Math.log(2)],["Math.log2(1024)",Math.log2(1024)],["Math.log10(1000)",Math.log10(1e3)],["Math.cbrt(2)",Math.cbrt(2)],["Math.hypot(3,4)",Math.hypot(3,4)],["Math.sinh(1)",Math.sinh(1)],["Math.cosh(1)",Math.cosh(1)],["Math.tanh(1)",Math.tanh(1)],["Math.expm1(1)",Math.expm1(1)],["Math.log1p(1)",Math.log1p(1)],["1e+308 overflow",1/0],["Number.EPSILON",Number.EPSILON],["Number.MAX_SAFE_INTEGER",Number.MAX_SAFE_INTEGER],["Number.MIN_SAFE_INTEGER",Number.MIN_SAFE_INTEGER],["0.1 + 0.2",.1+.2],["1/3",1/3],["Math.fround(1.1)",Math.fround(1.1)],["Math.clz32(1)",Math.clz32(1)],["Math.imul(3,4)",Math.imul(3,4)],["Math.trunc(-4.5)",Math.trunc(-4.5)],["Math.sign(-5)",Math.sign(-5)]],n=t.map(([e,t])=>[e,String(t),""]),i=e(t.map(([,e])=>String(e)).join(","));n.unshift(["FPU fingerprint hash",i,"cyan"]),
p.mathHash=i,o("body-math",n,"cnt-math")}function R(){l(93,"Reading performance metrics...");const e=[],t=performance;e.push(["timeOrigin",t.timeOrigin.toFixed(3)+" ms (Unix epoch offset)","dim"]),e.push(["now()",t.now().toFixed(3)+" ms (since page load)","green"]);const n=t.getEntriesByType("navigation")[0];n&&(e.push(["navType",n.type,""]),e.push(["redirectCount",String(n.redirectCount),""]),e.push(["DNS lookup",(n.domainLookupEnd-n.domainLookupStart).toFixed(2)+" ms",""]),e.push(["TCP connect",(n.connectEnd-n.connectStart).toFixed(2)+" ms",""]),e.push(["TLS handshake",(n.requestStart-n.secureConnectionStart>0?(n.requestStart-n.secureConnectionStart).toFixed(2):"0.00")+" ms",""]),e.push(["TTFB",(n.responseStart-n.requestStart).toFixed(2)+" ms","yellow"]),e.push(["DOM interactive",(n.domInteractive-n.startTime).toFixed(2)+" ms",""]),e.push(["DOM complete",(n.domComplete-n.startTime).toFixed(2)+" ms",""]),e.push(["Load event",(n.loadEventEnd-n.startTime).toFixed(2)+" ms","cyan"]),e.push(["transferSize",String(n.transferSize)+" bytes",""]),e.push(["decodedBodySize",String(n.decodedBodySize)+" bytes",""]),e.push(["protocol",n.nextHopProtocol||"(not exposed)","green"]),e.push(["renderBlockingStatus",n.renderBlockingStatus||"n/a",""])),t.getEntriesByType("paint").forEach(t=>{e.push([t.name,t.startTime.toFixed(2)+" ms","yellow"])});try{new PerformanceObserver(e=>{const t=e.getEntries();i("body-perf","LCP",t[t.length-1].startTime.toFixed(2)+" ms","green")}).observe({
type:"largest-contentful-paint",buffered:!0})}catch(e){}e.push(["PerformanceObserver",a("undefined"!=typeof PerformanceObserver),""]),o("body-perf",e,"cnt-perf")}function k(){l(96,"Probing input capabilities...");const e=[["maxTouchPoints",String(navigator.maxTouchPoints),navigator.maxTouchPoints>0?"yellow":""],["Touch Events API",a("ontouchstart"in window||navigator.maxTouchPoints>0),""],["Pointer Events API",a("undefined"!=typeof PointerEvent),""],["Mouse Events",a("undefined"!=typeof MouseEvent),""],["Keyboard Events",a("undefined"!=typeof KeyboardEvent),""],["navigator.keyboard",a("keyboard"in navigator),""],["DeviceOrientation",a("undefined"!=typeof DeviceOrientationEvent),""],["DeviceMotion",a("undefined"!=typeof DeviceMotionEvent),""],["Gamepad API",a("function"==typeof navigator.getGamepads),""],["Vibration API",a("function"==typeof navigator.vibrate),""],["Pen/stylus capable",a(window.matchMedia("(any-pointer:fine)").matches&&navigator.maxTouchPoints>0),""]];if("function"==typeof navigator.getGamepads){const t=Array.from(navigator.getGamepads()).filter(Boolean);e.push(["Connected gamepads",String(t.length),t.length>0?"green":""]),t.forEach((t,n)=>{e.push([`Gamepad ${n}`,`${t.id} — ${t.buttons.length} buttons, ${t.axes.length} axes`,"dim"])})}o("body-input",e,"cnt-input")}function D(){const e=document.getElementById("body-php"),t=document.createElement("pre");t.className="raw-block",t.textContent=JSON.stringify(PHP_DATA.server,null,2),e.appendChild(t),
document.getElementById("cnt-php").textContent=Object.keys(PHP_DATA.server||{}).length+" vars"}async function H(){l(95,"Running WebKit/Safari/Apple probes...");const e=[],t=navigator.userAgent,n=window,i=navigator,s=document,c=void 0!==n.safari;e.push(["window.safari object",a(c),c?"green":"dim"]);const u=void 0!==n.ApplePaySession;if(e.push(["ApplePaySession (Apple Pay)",a(u),u?"green":"dim"]),u)try{e.push(["ApplePay canMakePayments",a(n.ApplePaySession.canMakePayments()),n.ApplePaySession.canMakePayments()?"green":"yellow"]);let t=0;[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17].forEach(e=>{n.ApplePaySession.supportsVersion&&n.ApplePaySession.supportsVersion(e)&&(t=e)}),e.push(["ApplePaySession.supportsVersion max",t>0?String(t):"n/a","yellow"])}catch(t){e.push(["ApplePay probe error",t.message,"red"])}e.push(["GestureEvent (iOS exclusive)",a(void 0!==n.GestureEvent),void 0!==n.GestureEvent?"green":"dim"]);const h="undefined"!=typeof DeviceOrientationEvent&&"function"==typeof DeviceOrientationEvent.requestPermission;e.push(["DeviceOrientationEvent.requestPermission (iOS 13+)",a(h),h?"yellow":"dim"]);const m="undefined"!=typeof DeviceMotionEvent&&"function"==typeof DeviceMotionEvent.requestPermission;e.push(["DeviceMotionEvent.requestPermission (iOS 13+)",a(m),m?"yellow":"dim"]),e.push(["WebKitCSSMatrix",a(void 0!==n.WebKitCSSMatrix),""]),e.push(["window.webkitURL",a(void 0!==n.webkitURL),""]);const g=s.createElement("video"),f="function"==typeof g.webkitEnterFullscreen
;e.push(["HTMLVideoElement.webkitEnterFullscreen",a(f),f?"yellow":"dim"]);const v=void 0!==g.webkitSupportsFullscreen;e.push(["HTMLVideoElement.webkitSupportsFullscreen",a(v),""]),e.push(["webkitSpeechRecognition",a(void 0!==n.webkitSpeechRecognition),""]),e.push(["WebKitMutationObserver",a(void 0!==n.WebKitMutationObserver),""]),e.push(["webkitAudioContext",a(void 0!==n.webkitAudioContext),""]),e.push(["webkitIndexedDB",a(void 0!==n.webkitIndexedDB),""]),e.push(["webkitRTCPeerConnection",a(void 0!==n.webkitRTCPeerConnection),""]),e.push(["webkitRequestAnimationFrame",a(void 0!==n.webkitRequestAnimationFrame),""]),e.push(["WebKitMutationObserver",a(void 0!==n.WebKitMutationObserver),""]);const y=i.standalone;function w(e,t){return!(!CSS||!CSS.supports)&&CSS.supports(e,t)}e.push(["navigator.standalone (iOS PWA)",void 0===y?r("undefined — not iOS Safari","warn"):a(y),y?"green":""]),e.push(["window.orientation (deprecated iOS)",void 0!==n.orientation?String(n.orientation)+"°":r("undefined","dim"),void 0!==n.orientation?"yellow":""]),e.push(["CSS -webkit-backdrop-filter",a(w("-webkit-backdrop-filter","blur(1px)")),""]),e.push(["CSS -webkit-appearance: none",a(w("-webkit-appearance","none")),""]),e.push(["CSS -webkit-text-fill-color",a(w("-webkit-text-fill-color","red")),""]),e.push(["CSS -webkit-line-clamp",a(w("-webkit-line-clamp","2")),""]),e.push(["CSS -webkit-overflow-scrolling",a(w("-webkit-overflow-scrolling","touch")),""]),
e.push(["CSS -webkit-touch-callout",a(w("-webkit-touch-callout","none")),""]),e.push(["CSS color display-p3",a(w("color","color(display-p3 1 0 0)")),"green"]),e.push(["CSS backdrop-filter (unprefixed)",a(w("backdrop-filter","blur(1px)")),""]);const S=s.createElement("audio"),b=s.createElement("video"),P=(e,t)=>{try{return e.canPlayType(t)||"no"}catch(e){return"error"}};e.push(["audio/x-m4a (AAC-LC in M4A)",P(S,"audio/x-m4a"),""]),e.push(["audio/aac",P(S,"audio/aac"),""]),e.push(["audio/mp4; codecs=mp4a.40.2",P(S,"audio/mp4; codecs=mp4a.40.2"),""]),e.push(["video/mp4; codecs=hvc1",P(b,"video/mp4; codecs=hvc1"),"yellow"]),e.push(["video/mp4; codecs=dvh1.20.L153",P(b,"video/mp4; codecs=dvh1.20.L153"),""]),e.push(["HLS: application/vnd.apple.mpegurl",P(b,"application/vnd.apple.mpegurl"),"green"]),e.push(["HLS: application/x-mpegURL",P(b,"application/x-mpegURL"),""]),e.push(["video/mp4; codecs=avc1",P(b,"video/mp4; codecs=avc1"),""]),e.push(["video/mp4; codecs=hev1",P(b,"video/mp4; codecs=hev1"),""]),e.push(["document.hasStorageAccess API",a("function"==typeof s.hasStorageAccess),"function"==typeof s.hasStorageAccess?"yellow":""]),e.push(["document.requestStorageAccess",a("function"==typeof s.requestStorageAccess),""]);const A=s.createElement("canvas");A.width=20,A.height=20;const C=A.getContext("2d");C.fillStyle="#FF0000",C.fillRect(0,0,1,1);const M=C.getImageData(0,0,1,1).data,E=255!==M[0]||0!==M[1]||0!==M[2];e.push(["Canvas pixel noise detected",a(E),E?"yellow":""])
;const T=/WebKit/.test(t)&&!/Chromium/.test(t),x=/Safari/.test(t)&&!/Chrome/.test(t),I=/iPhone|iPad|iPod/.test(t)&&x,R=t.match(/OS (\d+)[_\.](\d+)/),k=t.match(/Version\/([\d.]+).*Safari/),D=t.match(/AppleWebKit\/([\d.]+)/);e.push(["UA: WebKit (not Chromium)",a(T),T?"green":"dim"]),e.push(["UA: Safari (not Chrome-based)",a(x),x?"green":"dim"]),e.push(["UA: Mobile Safari (iOS)",a(I),I?"green":"dim"]),e.push(["UA: iOS version",R?R[1]+"."+R[2]:"(not iOS)",R?"yellow":"dim"]),e.push(["UA: Safari version",k?k[1]:"(not in UA)",""]),e.push(["UA: AppleWebKit build",D?D[1]:"(not found)","cyan"]);const H=screen.width,F=screen.height;window.devicePixelRatio;let L="Unknown / not iOS";const O=[Math.min(H,F),Math.max(H,F)];[[[320,568],"iPhone SE (1st gen) / iPhone 5/5s"],[[375,667],"iPhone 6/7/8 / SE 2nd/3rd gen"],[[414,736],"iPhone 6+/7+/8+"],[[375,812],"iPhone X/XS/11 Pro / 12 mini / 13 mini"],[[414,896],"iPhone XR/XS Max/11/11 Pro Max"],[[390,844],"iPhone 12/13/14 Pro / 12/13"],[[428,926],"iPhone 12/13/14 Pro Max"],[[393,852],"iPhone 15/16 / 14 Pro"],[[430,932],"iPhone 15/16 Plus / 14 Pro Max"],[[402,874],"iPhone 16 Pro"],[[440,956],"iPhone 16 Pro Max"],[[768,1024],"iPad (non-retina) / iPad mini 1-3"],[[810,1080],"iPad 7th/8th/9th gen"],[[820,1180],"iPad Air 4/5"],[[834,1194],'iPad Pro 11"'],[[1024,1366],'iPad Pro 12.9"'],[[744,1133],"iPad mini 6"]].forEach(([[e,t],n])=>{O[0]===e&&O[1]===t&&(L=n)}),e.push(["iOS/iPadOS device hint",L,"Unknown / not iOS"!==L?"yellow":"dim"])
;const _=[c,u,void 0!==n.GestureEvent,h,m,void 0!==y,x,I].filter(Boolean),B=Math.round(_.length/8*100);e.push(["WebKit/Safari confidence score",B+"%",B>60?"green":B>30?"yellow":"dim"]),p.webkit=String(B)+"|"+(D?D[1]:"")+"|"+(k?k[1]:""),o("body-webkit",e,"cnt-webkit"),B>40&&d("🍎 WebKit: "+B+"%","ok")}async function F(){l(96,"Running Edge/Chromium-specific probes...");const e=[],t=window,n=navigator,i=n.userAgent,s=document,c=/Edg\//.test(i),u=/Edge\//.test(i),h=/Trident\//.test(i),m=/Chrome\//.test(i)&&!c&&!u,g=i.match(/Edg\/([\d.]+)/),f=i.match(/Chrome\/([\d.]+)/),v=i.match(/Trident\/([\d.]+)/);if(e.push(["UA: Chromium Edge (Edg/)",a(c),c?"green":"dim"]),e.push(["UA: EdgeHTML (legacy)",a(u),u?"yellow":"dim"]),e.push(["UA: Internet Explorer",a(h),h?"red":"dim"]),e.push(["UA: Chrome (not Edge)",a(m),m?"cyan":"dim"]),e.push(["Edge version",g?g[1]:"(not in UA)",g?"yellow":""]),e.push(["Chrome version",f?f[1]:"(not in UA)",""]),e.push(["Trident version (IE)",v?v[1]:"(none)",v?"red":"dim"]),n.userAgentData){const t=(n.userAgentData.brands||[]).map(e=>e.brand+"@"+e.version),o=t.join(", ");e.push(["UA-CH brands",o||"(empty)","cyan"]);const i=t.some(e=>e.includes("Microsoft Edge")),r=t.some(e=>e.includes("Google Chrome")),s=t.some(e=>e.includes("Chromium"));e.push(["Brand: Microsoft Edge",a(i),i?"green":"dim"]),e.push(["Brand: Google Chrome",a(r),r?"cyan":"dim"]),e.push(["Brand: Chromium",a(s),s?"dim":""]);try{
const t=await n.userAgentData.getHighEntropyValues(["architecture","bitness","model","wow64"]);e.push(["CH: architecture",t.architecture||"—","purple"]),e.push(["CH: bitness",t.bitness||"—","purple"]),e.push(["CH: model (OEM name)",t.model||"(blank — desktop)",""]),e.push(["CH: wow64 (32-on-64)",String(t.wow64),t.wow64?"yellow":""])}catch(t){e.push(["UA-CH high-entropy","(error: "+t.message+")","red"])}}else e.push(["UA-CH API (navigator.userAgentData)",r("NOT PRESENT","no"),"dim"]);const y=s.documentMode;function w(e,t){return!!(CSS&&CSS.supports&&CSS.supports(e,t))}e.push(["document.documentMode (IE)",null!=y?String(y):r("undefined","dim"),null!=y?"red":""]),e.push(["window.MSStream (IE/old Edge)",a(void 0!==t.MSStream),void 0!==t.MSStream?"yellow":""]),e.push(["window.msCrypto (IE11)",a(void 0!==t.msCrypto),void 0!==t.msCrypto?"yellow":""]),e.push(["window.msRequestAnimationFrame",a(void 0!==t.msRequestAnimationFrame),""]),e.push(["window.MSPointerEvent",a(void 0!==t.MSPointerEvent),""]),e.push(["window.external.msIsSiteMode",(()=>{try{return a(void 0!==t.external&&"function"==typeof t.external.msIsSiteMode)}catch(e){return r("blocked","warn")}})(),""]),e.push(["window.msWriteProfilerMark",a(void 0!==t.msWriteProfilerMark),""]),e.push(["window.chrome object",a(void 0!==t.chrome),void 0!==t.chrome?"green":"dim"]),t.chrome&&(e.push(["chrome.runtime",a(!!t.chrome.runtime),""]),e.push(["chrome.csi() (timing)",a("function"==typeof t.chrome.csi),""]),
e.push(["chrome.loadTimes() (legacy)",a("function"==typeof t.chrome.loadTimes),""]),e.push(["chrome.webstore (deprecated)",a(!!t.chrome.webstore),""]),e.push(["chrome.app",a(!!t.chrome.app),""])),e.push(["navigator.windowControlsOverlay",void 0!==n.windowControlsOverlay?n.windowControlsOverlay.visible?"visible (PWA window mode)":"present but hidden":r("undefined","dim"),void 0!==n.windowControlsOverlay?"yellow":""]),e.push(["window.getScreenDetails (Window Mgmt)",a("function"==typeof t.getScreenDetails),"function"==typeof t.getScreenDetails?"green":""]),e.push(["window.launchQueue (PWA Launch Handler)",a(void 0!==t.launchQueue),""]),e.push(["window.launchParams",a(void 0!==t.launchParams),""]),e.push(["navigator.registerProtocolHandler",a("function"==typeof n.registerProtocolHandler),""]),e.push(["PressureObserver (Compute Pressure)",a(void 0!==t.PressureObserver),void 0!==t.PressureObserver?"green":""]),e.push(["documentPictureInPicture API",a(void 0!==t.documentPictureInPicture),""]),e.push(["HTMLScriptElement.supports() — speculationrules",(()=>{try{return a(HTMLScriptElement.supports&&HTMLScriptElement.supports("speculationrules"))}catch(e){return r("error","warn")}})(),""]),e.push(["HTMLFencedFrameElement",a(void 0!==t.HTMLFencedFrameElement),""]),e.push(["navigator.storage.getDirectory (OPFS)",a(n.storage&&"function"==typeof n.storage.getDirectory),""]),e.push(["document.browsingTopics (Topics API)",a("function"==typeof s.browsingTopics),""]),
e.push(["window.attributionReporting",a(void 0!==t.attributionReporting),""]),e.push(["navigator.ink (Ink API)",a(void 0!==n.ink),void 0!==n.ink?"yellow":""]),e.push(["CSS -ms-overflow-style",a(w("-ms-overflow-style","none")),""]),e.push(["CSS -ms-high-contrast (legacy)",a(w("-ms-high-contrast","none")),""]),e.push(["CSS overscroll-behavior",a(w("overscroll-behavior","none")),""]),e.push(["CSS scrollbar-gutter",a(w("scrollbar-gutter","stable")),""]),e.push(["CSS accent-color",a(w("accent-color","red")),""]),e.push(["CSS zoom (non-standard)",a(w("zoom","1")),"yellow"]);const S=s.createElement("video"),b=e=>{try{return S.canPlayType(e)||r("no","no")}catch(e){return"error"}};e.push(["video/mp4; codecs=hvc1 (HEVC on Edge/Win)",b("video/mp4; codecs=hvc1"),""]),e.push(["video/mp4; codecs=av01 (AV1 on Edge/Win)",b("video/mp4; codecs=av01.0.05M.08"),""]),e.push(["video/webm; codecs=vp09 (VP9)",b("video/webm; codecs=vp09.00.10.08"),""]);const P=[c,u,void 0!==t.chrome,!!n.userAgentData,void 0!==n.windowControlsOverlay].filter(Boolean),A=Math.round(P.length/5*100);e.push(["Edge/Chromium confidence score",A+"%",A>60?"green":A>30?"yellow":"dim"]),p.edge=String(A)+"|"+(g?g[1]:"")+"|"+(f?f[1]:""),o("body-edge",e,"cnt-edge"),A>40&&d("🔷 Edge: "+A+"%","ok")}async function L(){l(97,"Running Firefox/Gecko probes...")
;const e=[],t=window,n=navigator,i=n.userAgent,s=document,c=/Firefox\//.test(i),u=/Gecko\//.test(i)&&!/like Gecko/.test(i.split("Gecko/")[1]||""),h=/LibreWolf/.test(i),m=/Waterfox/.test(i),g=/PaleMoon|Goanna/.test(i),f=i.match(/Firefox\/([\d.]+)/),v=i.match(/rv:([\d.]+)/),y=i.match(/Gecko\/(20\d{6}|\d+\.\d+)/);e.push(["UA: Firefox",a(c),c?"green":"dim"]),e.push(['UA: Gecko (not "like Gecko")',a(u),u?"green":"dim"]),e.push(["UA: LibreWolf",a(h),h?"yellow":"dim"]),e.push(["UA: Waterfox",a(m),m?"yellow":"dim"]),e.push(["UA: Pale Moon / Goanna",a(g),g?"yellow":"dim"]),e.push(["UA: Tor Browser pattern (FF + rv:)",a(c&&!!v),c&&v?"yellow":"dim"]),e.push(["Firefox version",f?f[1]:"(not in UA)",f?"yellow":""]),e.push(["Gecko rv: version",v?v[1]:"(not in UA)",""]),e.push(["Gecko build date",y?y[1]:"(not in UA)",""]);const w=n.buildID;e.push(["navigator.buildID (Gecko-only)",w||r("undefined — not Firefox","dim"),w?"green":""]);const S=n.oscpu;e.push(["navigator.oscpu (Gecko-only)",S||r("undefined — not Firefox","dim"),S?"green":""]),e.push(["window.sidebar (Firefox/Netscape)",a(void 0!==t.sidebar),void 0!==t.sidebar?"yellow":""]),e.push(["window.netscape (Netscape/FF legacy)",a(void 0!==t.netscape),void 0!==t.netscape?"yellow":""]),e.push(["window.Components (Firefox XUL/priv.)",a(void 0!==t.Components),void 0!==t.Components?"red":""]),e.push(["window.controllers (Firefox XUL)",a(void 0!==t.controllers),""]),
e.push(["window.InstallTrigger (Firefox canonical)",a(void 0!==t.InstallTrigger),void 0!==t.InstallTrigger?"green":""]),e.push(["window.mozIndexedDB",a(void 0!==t.mozIndexedDB),""]),e.push(["window.mozRTCPeerConnection",a(void 0!==t.mozRTCPeerConnection),""]),e.push(["window.mozRTCSessionDescription",a(void 0!==t.mozRTCSessionDescription),""]),e.push(["window.mozRTCIceCandidate",a(void 0!==t.mozRTCIceCandidate),""]),e.push(["window.MozMutationObserver",a(void 0!==t.MozMutationObserver),""]),e.push(["document.mozFullScreenElement",a(void 0!==s.mozFullScreenElement),""]),e.push(["document.mozFullScreen",a(void 0!==s.mozFullScreen),""]);const b=s.createElement("div");function P(e,t){return!!(CSS&&CSS.supports&&CSS.supports(e,t))}e.push(["element.mozMatchesSelector",a("function"==typeof b.mozMatchesSelector),""]),e.push(["navigator.taintEnabled (pre-FF65)",a("function"==typeof n.taintEnabled),""]),e.push(["navigator.mozIsLocallyAvailable",a("function"==typeof n.mozIsLocallyAvailable),""]),e.push(["CSS -moz-appearance: none",a(P("-moz-appearance","none")),void 0!==t.InstallTrigger?"green":""]),e.push(["CSS display: -moz-box",a(P("display","-moz-box")),""]),e.push(["CSS display: -moz-inline-box",a(P("display","-moz-inline-box")),""]),e.push(["CSS -moz-osx-font-smoothing",a(P("-moz-osx-font-smoothing","grayscale")),""]),e.push(["CSS scrollbar-width: thin",a(P("scrollbar-width","thin")),""]),e.push(["CSS scrollbar-color",a(P("scrollbar-color","red blue")),""]),
e.push(["CSS image-rendering: -moz-crisp-edges",a(P("image-rendering","-moz-crisp-edges")),""]),e.push(["CSS -moz-text-decoration-color",a(P("-moz-text-decoration-color","red")),""]),e.push(["CSS text-decoration-skip-ink",a(P("text-decoration-skip-ink","auto")),""]);const A=s.createElement("canvas");A.width=100,A.height=1;const C=A.getContext("2d");C.fillStyle="rgba(123, 45, 67, 0.89)",C.fillRect(0,0,100,1);const M=C.getImageData(50,0,1,1).data,E=[138,68,88,255],T=M[0]!==E[0]||M[1]!==E[1]||M[2]!==E[2];e.push(["Firefox RFP: canvas noise detected",a(T),T?"yellow":""]),e.push(["RFP pixel got",`rgba(${M[0]},${M[1]},${M[2]},${M[3]})`,"dim"]),e.push(["RFP pixel expected",`rgba(${E.join(",")})`,"dim"]);const x=Intl.DateTimeFormat().resolvedOptions().timeZone,I="UTC"===x||"Etc/UTC"===x;e.push(["RFP: timezone forced to UTC",a(I),I?"yellow":""]);const R=1366===screen.width&&768===screen.height;e.push(["RFP: screen clamped to 1366×768",a(R),R?"yellow":""]);const k=2===n.hardwareConcurrency;e.push(["RFP: hardwareConcurrency forced to 2",a(k),k?"yellow":""]);const D=[T,I,R,k].filter(Boolean).length;e.push(["Firefox RFP active estimate",D>=2?r("LIKELY ACTIVE ("+D+"/4 signals)","warn"):r("probably OFF ("+D+"/4)","item"),""]);const H=s.createElement("audio"),F=s.createElement("video"),L=(e,t)=>{try{return e.canPlayType(t)||r("no","no")}catch(e){return"error"}};e.push(["audio/ogg; codecs=vorbis",L(H,"audio/ogg; codecs=vorbis"),""]),
e.push(["audio/ogg; codecs=opus",L(H,"audio/ogg; codecs=opus"),"green"]),e.push(["audio/ogg; codecs=flac",L(H,"audio/ogg; codecs=flac"),""]),e.push(["video/ogg; codecs=theora",L(F,"video/ogg; codecs=theora"),""]),e.push(["video/webm; codecs=vp8,vorbis",L(F,"video/webm; codecs=vp8,vorbis"),""]),e.push(["video/webm; codecs=vp9",L(F,"video/webm; codecs=vp9"),""]),e.push(["video/webm; codecs=av1",L(F,"video/webm; codecs=av01.0.05M.08"),""]),e.push(["video/mp4; codecs=hvc1 (HEVC — FF usually no)",L(F,"video/mp4; codecs=hvc1"),""]),e.push(["HTMLInputElement.showPicker",a("function"==typeof s.createElement("input").showPicker),""]),e.push(["Sanitizer API",a(void 0!==t.Sanitizer),""]),e.push(["showOpenFilePicker (FSAA)",a("function"==typeof t.showOpenFilePicker),""]),e.push(["window.Profiler (FF DevTools)",a(void 0!==t.Profiler),""]),e.push(["navigator.getAutoplayPolicy",a("function"==typeof n.getAutoplayPolicy),"function"==typeof n.getAutoplayPolicy?"yellow":""]);const O=[c,!!w,!!S,void 0!==t.sidebar,void 0!==t.InstallTrigger,P("-moz-appearance","none")].filter(Boolean),_=Math.round(O.length/6*100);e.push(["Firefox/Gecko confidence score",_+"%",_>60?"green":_>30?"yellow":"dim"]),p.firefox=String(_)+"|"+(f?f[1]:"")+"|"+(S||"")+"|rfp:"+D,o("body-firefox",e,"cnt-firefox"),_>40&&d("🦊 Firefox: "+_+"%","ok")}function toggleTheme(){const e=document.documentElement,t=document.getElementById("theme-icon"),n=document.getElementById("theme-label");e.classList.toggle("light")
;const o=e.classList.contains("light");t.textContent=o?"🌙":"☀",n.textContent=o?"dark":"light";try{localStorage.setItem("bp-theme",o?"light":"dark")}catch(e){}}function O(){const e=navigator.userAgent,t=navigator,n=window;function o(e,t,n,o){document.getElementById("iv-"+e).textContent=t||"—",document.getElementById("is-"+e).textContent=n||" ",document.getElementById("iconf-"+e).className="intel-conf "+(o||"none")}!function(){let i="?",r="",a="low";if(t.userAgentData&&t.userAgentData.brands){const e=t.userAgentData.brands,n=e.filter(e=>!/Not.A.Brand|Chromium/i.test(e.brand)&&""!==e.brand.trim());if(n.length)i=n[0].brand,r="v"+n[0].version,a="high";else{const t=e.find(e=>/Chromium/i.test(e.brand));t&&(i="Chromium",r="v"+t.version,a="medium")}}if(void 0!==t.buildID&&t.buildID){const t=e.match(/Firefox\/([\d.]+)/);i="Firefox",r=t?"v"+t[1]:"",a="high",/LibreWolf/i.test(e)&&(i="LibreWolf",a="high"),/Waterfox/i.test(e)&&(i="Waterfox",a="high"),/PaleMoon/i.test(e)&&(i="Pale Moon",a="high")}if(void 0!==n.safari&&!/Chrome/.test(e)){const t=e.match(/Version\/([\d.]+).*Safari/);i="Safari",r=t?"v"+t[1]:"",a="high",/Mobile.*Safari|iPhone|iPad|iPod/.test(e)&&(i="Mobile Safari")}if("?"===i||"Chromium"===i){
const t=[[/OPR\/([\d.]+)/,"Opera","medium"],[/Vivaldi\/([\d.]+)/,"Vivaldi","high"],[/YaBrowser\/([\d.]+)/,"Yandex Browser","high"],[/Brave/,"Brave","medium"],[/Edg\/([\d.]+)/,"Edge","high"],[/Chrome\/([\d.]+)/,"Chrome","medium"],[/Firefox\/([\d.]+)/,"Firefox","medium"],[/Safari\/([\d.]+)/,"Safari","medium"],[/MSIE ([\d.]+)/,"Internet Explorer","high"],[/Trident.*rv:([\d.]+)/,"Internet Explorer","high"]];for(const[n,o,s]of t){const t=e.match(n);if(t){"?"!==i&&"high"!==s||(i=o,r=t[1]?"v"+t[1].split(".")[0]:"",a=s);break}}}t.brave&&"function"==typeof t.brave.isBrave&&(i="Brave",r="",a="high"),o("browser",i,r,a)}(),function(){let n="?",i="",r="low";if(void 0!==t.buildID&&t.buildID){n="Gecko";const t=e.match(/rv:([\d.]+)/);i=t?"rv:"+t[1]:"",r="high"}else if(/WebKit/.test(e)&&!/Chrome/.test(e)){const t=e.match(/AppleWebKit\/([\d.]+)/);n="WebKit",i=t?t[1]:"",r="high"}else if(/Chrome/.test(e)){const o=e.match(/AppleWebKit\/([\d.]+)/);n="Blink",i=o?"(wk "+o[1]+")":"",r=t.userAgentData?"high":"medium"}else if(/Trident/.test(e)){const t=e.match(/Trident\/([\d.]+)/);n="Trident",i=t?t[1]:"",r="high"}else if(/Edge\//.test(e)){const t=e.match(/Edge\/([\d.]+)/);n="EdgeHTML",i=t?t[1]:"",r="high"}o("engine",n,i,r)}(),function(){let n="?",i="",r="low";const a=t.platform||"";if(/iPhone|iPod/.test(a)?(n="iOS",r="high"):/iPad/.test(a)?(n="iPadOS",r="high"):/MacIntel|MacPPC/.test(a)?(n="macOS",r="medium"):/Win/.test(a)?(n="Windows",r="medium"):/Linux/.test(a)&&(n="Linux",r="medium"),p.uaCH)try{
const e=JSON.parse(p.uaCH);if(e.platform){const t=e.platform.toLowerCase();if(/win/i.test(t)){if(n="Windows",r="high",e.platformVersion){const[t]=e.platformVersion.split(".");i=+t>=13?"v11+":+t>=10?"v10":"v8/8.1"}}else/macos|mac os/i.test(t)?(n="macOS",r="high",e.platformVersion&&(i=e.platformVersion.split(".").slice(0,2).join("."))):/android/i.test(t)?(n="Android",r="high",e.platformVersion&&(i=e.platformVersion)):/chromeos|cros/i.test(t)?(n="ChromeOS",r="high"):/linux/i.test(t)&&"Linux"===n&&(r="medium")}}catch(e){}if(t.oscpu&&"?"===n&&(n=t.oscpu.split(" ").slice(0,2).join(" "),r="high"),"?"===n||"Linux"===n){const t=e.match(/Android ([\d.]+)/i);if(t)n="Android",i=i||t[1].split(".").slice(0,2).join("."),r="high";else if("?"===n){const t=[[/Windows NT 10\.0/,"Windows","v10/11","medium"],[/Windows NT 6\.3/,"Windows","v8.1","medium"],[/Windows NT 6\.2/,"Windows","v8","medium"],[/Windows NT 6\.1/,"Windows","v7","medium"],[/iPad.*OS ([\d_]+)/,"iPadOS","","high"],[/iPhone.*OS ([\d_]+)/,"iOS","","high"],[/Mac OS X ([\d_]+)/,"macOS","","medium"],[/CrOS/,"ChromeOS","","medium"]];for(const[o,a,s,c]of t){const t=e.match(o);if(t){n=a,i=s||(t[1]?t[1].replace(/_/g,".").split(".").slice(0,2).join("."):""),r=c;break}}}}o("os",n,i,r)}(),function(){let n="?",i="",r="low";const a=t.platform||"";let s="?"
;/armv8|aarch64|arm64/i.test(a)?s="ARM64":/armv7|armv6|armv5/i.test(a)?s="ARM32":/arm/i.test(a)&&/64/.test(a)?s="ARM64":/arm/i.test(a)?s="ARM":/x86_64|x86-64|amd64/i.test(a)?s="x86-64":/i[3-6]86|x86_32/i.test(a)?s="x86-32":/Win64/i.test(a)?s="x86-64":/Win32/i.test(a)?s="x86 (32/64)":/iPhone|iPad|iPod/.test(a)?s="ARM64":/MacIntel/.test(a)?s="x86-64":/MacPPC/.test(a)&&(s="PowerPC");let c="?";const d=(p.gpuRenderer||"")+" "+(p.gpuVendor||"");/Mali/i.test(d)||/Adreno/i.test(d)||/PowerVR/i.test(d)?c="ARM":/Apple (GPU|M[0-9])/i.test(d)?c="ARM64":(/NVIDIA|GeForce|Quadro/i.test(d)||/Intel.*((U?HD|Iris|Arc)|Graphics)/i.test(d)||/AMD|Radeon/i.test(d)&&!/Mali/i.test(d))&&(c="x86");let l="?";if(p.uaCH)try{const e=JSON.parse(p.uaCH);if(e.architecture){const t=e.architecture,n=e.bitness||"";l=/arm/i.test(t)?"64"===n?"ARM64":"ARM32":/x86/i.test(t)&&"64"===n?"x86-64":/x86/i.test(t)?"x86-32":t+(n?"-"+n:"")}}catch(e){}let u="?";t.oscpu&&(/x86_64|x86-64|amd64/i.test(t.oscpu)?u="x86-64":/i[3-6]86/i.test(t.oscpu)?u="x86-32":/aarch64|arm64/i.test(t.oscpu)?u="ARM64":/armv/i.test(t.oscpu)&&(u="ARM32"));let h="?";/Win64|WOW64/i.test(e)||/x86_64|x86-64|amd64/i.test(e)?h="x86-64":/ARM|aarch64/i.test(e)?h="ARM64":/Win32/i.test(e)&&(h="x86 (32/64)");const m=[];if("?"!==s?(n=s,r="high",i="platform API"):"?"!==u?(n=u,r="high",i="oscpu (Firefox)"):"?"!==l?(n=l,r="medium",i="UA-CH hint"):"?"!==h&&(n=h,r="low",i="UA string (unreliable)"),"?"!==c&&"?"!==n){
const e="ARM"===c||"ARM64"===c,t=/ARM/i.test(n),o="x86"===c,a=/x86/i.test(n);if(e&&a||o&&t)m.push("GPU↔platform conflict"),e&&a&&"medium"===r&&"?"!==l&&"?"===s&&(n=c.includes("64")?"ARM64":"ARM",r="medium"),i=m.join(" · "),"high"===r?r="medium":"medium"===r&&(r="low");else{"medium"===r&&"?"!==c&&(r="high"),"low"===r&&"?"!==c&&(r="medium");const t=e?"GPU corroborates":"";t&&!i.includes("corr")&&(i=i?i+" · "+t:t)}}else"?"!==c&&"?"===n&&(n=c,r="low",i="GPU vendor only");if("ARM"===n&&"ARM64"===c&&(n="ARM64"),"x86-64"===s&&/Apple (GPU|M[0-9])/i.test(d)&&(i="Rosetta 2 (x86 binary on Apple Silicon)",r="medium"),p.uaCH)try{JSON.parse(p.uaCH).wow64&&(i=(i?i+" · ":"")+"WoW64 (32-bit process on 64-bit OS)")}catch(e){}o("arch",n||"?",i,r)}(),function(){let n="?",i="",r="low";const a=t.maxTouchPoints>0,s=window.matchMedia("(pointer:fine)").matches,c=window.matchMedia("(pointer:coarse)").matches,d=window.matchMedia("(any-pointer:fine)").matches,l=window.matchMedia("(any-pointer:coarse)").matches,p=t.standalone,u=t.platform||"",h=/Mobile|Android.*Mobile|iPhone|iPod/i.test(e),m=/iPad|Tablet/i.test(e)||/iPad/.test(u)||"MacIntel"===t.platform&&t.maxTouchPoints>1,g=/Android/i.test(e),f=g&&/Mobile/i.test(e),v=g&&!/Mobile/i.test(e);/iPhone|iPod/.test(u)||/iPhone|iPod/.test(e)?(n="Mobile",i="iPhone",r="high"):/iPad/.test(u)||m?(n="Tablet",i="iPad / iPadOS",r="high"):v?(n="Tablet",i="Android tablet",r="high"):f?(n="Mobile",i="Android phone",r="high"):h?(n="Mobile",i="mobile UA",
r="medium"):a||!s||l?a&&c&&!s&&!d?(n="Mobile/Tablet",r="medium",i="touch+coarse pointer"):a&&s?(n="Hybrid",r="medium",i="2-in-1 (touch+fine pointer)"):(n="Desktop",r="low",i="assumed"):(n="Desktop",r="high",/MacIntel|MacPPC/.test(u)?i="Mac":/Win/.test(u)?i="PC":/Linux/.test(u)&&!g&&(i="Linux workstation")),t.maxTouchPoints>0&&"?"!==n&&(i+=i?" · "+t.maxTouchPoints+"pt touch":t.maxTouchPoints+"pt touch"),p&&(i+=i?" · PWA":"PWA installed"),o("device",n,i,r)}(),function(){const e=window.devicePixelRatio||1,t=screen.width,n=screen.height;Math.round(t/e),Math.round(n/e);let i="sRGB";window.matchMedia("(color-gamut:rec2020)").matches?i="Rec.2020":window.matchMedia("(color-gamut:p3)").matches&&(i="P3 wide"),o("display",t+"×"+n,(1!==e?e+"x DPR · ":"")+i+(window.matchMedia("(dynamic-range:high)").matches?" · HDR":""),e>0&&t>0?"high":"medium")}(),function(){let e="?",t="",n="none";if(p.gpuRenderer){let o=p.gpuRenderer.replace(/ANGLE \(/,"").replace(/\)$/,"").replace(/Direct3D.*$/,"").trim();const i=p.gpuVendor||"";/NVIDIA/i.test(o+i)?t="NVIDIA":/AMD|Radeon/i.test(o)?t="AMD":/Intel/i.test(o+i)?t="Intel":/Apple/i.test(o+i)?t="Apple GPU":/Adreno/i.test(o)?t="Qualcomm":/Mali/i.test(o)?t="ARM Mali":/PowerVR/i.test(o)?t="PowerVR":/llvmpipe|softpipe|swrast/i.test(o)&&(t="Software renderer"),e=o.length>24?o.substring(0,22)+"…":o,n="high"}else p.webglRender?(e="WebGL (masked)",t="unmasked renderer blocked",n="low"):(e="Not available",n="none");o("gpu",e,t,n)}(),function(){
const e=t.hardwareConcurrency||0,n=t.deviceMemory;let i="",r="",a="low";e>0&&null!=n?(i=e+" cores",r=n+" GB RAM (bucket)",a="medium"):e>0?(i=e+" logical cores",r="RAM not exposed",a="medium"):(i="Not exposed",a="none"),void 0!==t.buildID&&t.buildID&&2===e&&(r+=" (possibly clamped by RFP)",a="low"),o("hw",i,r,a)}(),function(){const e=Intl.DateTimeFormat().resolvedOptions().timeZone||"?",n=t.language||"?",i=-(new Date).getTimezoneOffset();o("locale",n,e+" · UTC"+(i>=0?"+":"")+Math.floor(i/60)+":"+String(Math.abs(i%60)).padStart(2,"0"),"UTC"!==e&&"Etc/UTC"!==e||void 0===t.buildID||!t.buildID?"high":"low")}(),function(){let e="?",n="",i="low",r=0;(function(){const e=document.createElement("canvas");e.width=20,e.height=1;const t=e.getContext("2d");t.fillStyle="#FF0000",t.fillRect(0,0,1,1);const n=t.getImageData(0,0,1,1).data;return 255!==n[0]||0!==n[1]||0!==n[2]})()&&r++,1366===screen.width&&768===screen.height&&r++,"1"===t.doNotTrack&&r++,t.globalPrivacyControl&&r++,t.webdriver?(e="Automated / Bot",i="high",n="webdriver=true"):r>=3?(e="High Privacy",i="high",n=r+" RFP signals"):2===r?(e="Privacy Tools",i="medium",n=r+" signals"):1===r?(e="Some Privacy",i="low",n="1 signal (DNT/GPC?)"):(e="Standard",i="high",n="no RFP signals"),o("privacy",e,n,i)}()}function copyHash(){const e=document.getElementById("master-hash").textContent,t=e=>d(e?"⧉ Hash copied to clipboard":"⧉ Copy failed",e?"ok":"err")
;if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(e).then(()=>t(!0),()=>t(!1));else try{const n=document.createElement("textarea");n.value=e,n.style.position="fixed",n.style.opacity="0",document.body.appendChild(n),n.select(),document.execCommand("copy"),n.remove(),t(!0)}catch(e){t(!1)}}function exportReport(){const e={};document.querySelectorAll(".section").forEach(t=>{const n=(t.querySelector(".section-header .title")||{}).textContent||t.id,o=[];t.querySelectorAll(".section-body .row").forEach(e=>{const t=e.querySelector(".row-key"),n=e.querySelector(".row-val");t&&n&&o.push([t.textContent.trim(),n.textContent.trim()])}),e[n]=o});const t={tool:"BrowserPrint",version:"4.2",generatedUtc:(new Date).toISOString(),masterHash:p.stableHash||null,sessionHash:p.sessionHash||null,rawSignals:p,serverSide:PHP_DATA,sections:e},n=new Blob([JSON.stringify(t,null,2)],{type:"application/json"}),o=document.createElement("a");o.href=URL.createObjectURL(n),o.download="browserprint-"+(p.stableHash||"report")+".json",document.body.appendChild(o),o.click(),setTimeout(()=>{URL.revokeObjectURL(o.href),o.remove()},1e3),d("⇓ Report exported","ok")}function _(){const e=e=>(document.getElementById(e)||{}).textContent||"";return{hashes:{stable:p.stableHash||null,session:p.sessionHash||null},intelBar:{browser:e("iv-browser")+" "+e("is-browser").trim(),engine:e("iv-engine")+" "+e("is-engine").trim(),os:e("iv-os")+" "+e("is-os").trim(),
arch:e("iv-arch")+" "+e("is-arch").trim(),device:e("iv-device")+" "+e("is-device").trim(),display:e("iv-display")+" "+e("is-display").trim(),gpu:e("iv-gpu")+" "+e("is-gpu").trim(),hw:e("iv-hw")+" "+e("is-hw").trim(),locale:e("iv-locale")+" "+e("is-locale").trim(),privacy:e("iv-privacy")+" "+e("is-privacy").trim()},signals:p,server:{remote_addr:PHP_DATA.remote_addr||null,forwarded_for:PHP_DATA.forwarded_for||null,headers:PHP_DATA.headers||{}},client:{userAgent:navigator.userAgent,secureContext:window.isSecureContext,uaCH:p.uaCH?JSON.parse(p.uaCH):null}}}async function B(){const e=document.getElementById("body-ai");if(!e)return;e.innerHTML='<div class="row"><span class="row-key">AI analyst</span><span class="row-val dim">Analysing fingerprint…</span></div>';const t=_();let n=null,o="";try{const e=await fetch(location.pathname+"?action=ai-summary",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({report:t})}),i=await e.json();i&&i.ok&&i.summary&&(n=i.summary,o="remote model: "+(i.model||"configured endpoint"))}catch(e){}n||(n=N(t),o="local heuristic engine (configure $BP_AI in fingerprint.php for LLM analysis)"),e.innerHTML="";const i=document.createElement("div");i.className="row",i.innerHTML='<span class="row-key">Deductions</span><span class="row-val" style="white-space:normal">'+s(n)+"</span>",e.appendChild(i);const r=document.createElement("div");r.className="row",
r.innerHTML='<span class="row-key">Source</span><span class="row-val dim">'+s(o)+"</span>",e.appendChild(r);const a=document.getElementById("cnt-ai");a&&(a.textContent=o.startsWith("remote")?"AI":"local")}function N(e){const t=[],n=e.intelBar,o=e.client.userAgent,i=e.signals,r=(n.browser||"").trim();t.push("This is most likely "+(r&&"—"!==r?r:"an unidentified browser")+(n.engine&&"—"!==n.engine.trim()?" on the "+n.engine.trim().split(" ")[0]+" engine":""));const a=(n.os||"").trim(),s=(n.arch||"").trim();a&&"—"!==a&&t.push("running on "+a+(s&&"—"!==s?" ("+s+")":""));const c=[];i.hw_concurrency&&"0"!==i.hw_concurrency&&c.push(i.hw_concurrency+" logical cores"),i.device_memory&&"?"!==i.device_memory&&c.push("~"+i.device_memory+" GB RAM (bucketed)"),i.gpuRenderer&&c.push("GPU: "+String(i.gpuRenderer).substring(0,64).replace(/[ (][^ )]*$/,"")),c.length&&t.push("with "+c.join(", "));const d=(n.device||"").trim();d&&"—"!==d&&!/^Desktop/.test(d)&&t.push("— a "+d.toLowerCase()+" form factor"),i.screen&&t.push("display "+i.screen.replace("x","×").replace("@"," @ DPR "));const l=[];i.uaCH&&l.push("full UA Client Hints available (Chromium family confirmed)"),i.fonts&&l.push("font profile hash "+i.fonts),i.mediaDevices&&"0"!==i.mediaDevices&&l.push(i.mediaDevices+" media device(s) visible"),i.voices&&"0"!==i.voices&&l.push(i.voices+" speech voices"),l.length&&t.push("; notable: "+l.join("; "));const p=[];i.gpuRenderer||p.push("GPU renderer masked (WebGL debug info blocked)"),
i.uaCH||p.push("no UA-CH → not Chromium, or headers/API suppressed"),i.audio||p.push("audio fingerprint blocked"),""!==i.rtcIPs&&i.rtcIPs||p.push("local IPs hidden (mDNS .local obfuscation)"),!1===e.client.secureContext&&p.push("insecure context — several probes unavailable (serve over HTTPS)");const u=(n.privacy||"").trim();return/privacy|RFP|Automated/i.test(u)&&p.push("anti-fingerprinting signals: "+u),/firefox/i.test(o)&&i.firefox&&/rfp:[1-4]/.test(i.firefox)&&p.push("Firefox Resist-Fingerprinting likely ACTIVE (expect clamped values)"),p.length&&t.push(". Blind spots/obfuscation: "+p.join("; ")),(t.join(" ").replace(/\s+;/g,";").replace(/\s+/g," ")+".").replace(/\.\./g,".")}function W(){const e=[p.userAgent||"",p.platform||"",p.canvas||"",p.webglRender||"",p.gpuRenderer||"",p.audio||"",p.fonts||"",p.timezone||"",p.locale||"",p.screen||"",p.mathHash||"",p.featHash||"",p.hw_concurrency||"",p.device_memory||"",p.uaCH||"",p.webkit||"",p.edge||"",p.firefox||""],t=e.concat([p.remoteAddr||"",PHP_DATA.remote_addr||"",p.forwardedFor||"",p.voices||"",p.battery||"",p.rtcIPs||""]);p.stableHash=n(e),p.sessionHash=n(t),document.getElementById("master-hash").textContent=p.stableHash;const o=document.getElementById("session-hash");o&&(o.textContent=p.sessionHash),O();const i=e.filter(e=>e.length>0).length,r=Math.round(2.8*i);document.getElementById("entropy-score").innerHTML=`<span class="status-chip info">~${r} bits entropy · ${i}/${e.length} stable signals</span>`,
d("⬡ UA-CH: "+(p.uaCH?"full":"basic"),p.uaCH?"ok":"warn"),d("🎨 Canvas: "+(p.canvas?"✓":"✗"),p.canvas?"ok":"err"),d("🎮 WebGL: "+(p.gpuRenderer?p.gpuRenderer.split("/")[0].substring(0,20):"masked"),p.gpuRenderer?"ok":"warn"),d("🔊 Audio: "+(p.audio?"✓":"✗"),p.audio?"ok":"err")}async function U(e,t){try{await t()}catch(t){console.error("[BrowserPrint] collector failed:",e,t),d("⚠ "+e+": "+(t&&t.message?t.message:"error"),"err")}}async function G(){await U("identity",u),U("headers",h),U("screen",m),U("canvas",g),U("webgl",f),await Promise.all([U("audio",v),U("battery",b),U("media",A),U("permissions",M)]),U("fonts",y),U("locale",w),U("network",S),U("storage",P),await Promise.all([U("speech",C),U("webrtc",E)]),U("css",T),U("features",x),U("math",I),U("perf",R),U("input",k),await Promise.all([U("webkit",H),U("edge",F),U("firefox",L)]),U("phpRaw",D),l(99,"Computing master fingerprint..."),U("masterHash",W),l(100,"Done."),d("🔒 Context: "+(window.isSecureContext?"secure":"INSECURE — some probes limited"),window.isSecureContext?"ok":"warn"),B()}function V(){const e=document.getElementById("loader");e&&(e.classList.add("done"),setTimeout(()=>e.remove(),500))}!function(){try{"light"===localStorage.getItem("bp-theme")&&document.documentElement.classList.add("light")}catch(e){}}(),window.addEventListener("error",V),window.addEventListener("unhandledrejection",V),window.addEventListener("DOMContentLoaded",()=>{try{if("light"===localStorage.getItem("bp-theme")){
document.documentElement.classList.add("light");const e=document.getElementById("theme-icon"),t=document.getElementById("theme-label");e&&(e.textContent="🌙"),t&&(t.textContent="dark")}}catch(e){}G().catch(e=>console.error("[BrowserPrint] main() failed:",e)).finally(()=>setTimeout(V,300))});
</script>

</body>
</html>
