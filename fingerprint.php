<?php
/**
 * browserprint.php — Comprehensive Browser & System Fingerprinting Tool
 * For private intranet use only. Jason C. Kay / solarian design
 *
 * Collects every available signal: HTTP headers, UA client hints, canvas,
 * WebGL, audio, fonts, WebRTC, battery, media, permissions, CSS features,
 * math/FPU variance, performance, storage, speech synthesis, and more.
 */

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
<style>
  /* ── Fonts ─────────────────────────────────────────────────────────── */
  /* Google Fonts removed — intranet safe mode, using system fallbacks */

/* ── Variables ──────────────────────────────────────────────────────── */
:root {
--bg:        #090c10;
--bg2:       #0d1117;
--bg3:       #161b22;
--border:    #21262d;
--green:     #39d353;
--green-dim: #1a6b26;
--cyan:      #58d4f0;
--cyan-dim:  #1e5a6e;
--yellow:    #e3b341;
--red:       #f85149;
--purple:    #bc8cff;
--text:      #c9d1d9;
--text-dim:  #6e7681;
--glow:      0 0 8px rgba(57,211,83,0.35);
--glow-c:    0 0 8px rgba(88,212,240,0.35);
}

/* ── Reset & Base ───────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; }

body {
background-color: #090c10; /* explicit — no var(), no !important (WebKit shorthand+var+!important bug) */
color: #c9d1d9;
font-family: 'Consolas', 'Fira Code', 'Courier New', monospace;
font-size: 13px;
line-height: 1.6;
min-height: 100vh;
padding: 0 0 60px 0;
background-image:
radial-gradient(ellipse at 20% 0%, rgba(57,211,83,0.04) 0%, transparent 60%),
radial-gradient(ellipse at 80% 100%, rgba(88,212,240,0.03) 0%, transparent 60%);
}

/* ── Header ─────────────────────────────────────────────────────────── */
#masthead {
background: #0d1117; /* explicit dark */
/* (was CSS variable — now explicit) */
border-bottom: 1px solid #21262d;
padding: 24px 32px 20px;
position: sticky;
top: 0;
z-index: 100;
-webkit-backdrop-filter: blur(8px); /* Safari ≤15 / older WebKit */
backdrop-filter: blur(8px);
}

#masthead h1 {
font-family: 'Consolas', 'Lucida Console', monospace; letter-spacing: 0.06em;
font-size: 18px;
font-weight: 900;
letter-spacing: 0.12em;
color: #39d353;
text-shadow: 0 0 8px rgba(57,211,83,0.35);
display: flex;
align-items: center;
gap: 12px;
}

#masthead h1 span.ver {
font-size: 10px;
color: #6e7681;
font-family: 'Consolas', 'Courier New', monospace;
font-weight: 400;
letter-spacing: 0.05em;
}

#hash-bar {
margin-top: 10px;
display: flex;
align-items: center;
gap: 12px;
flex-wrap: wrap;
}

#hash-bar .label {
color: #6e7681;
font-size: 11px;
text-transform: uppercase;
letter-spacing: 0.1em;
}

#master-hash {
font-family: 'Consolas', 'Lucida Console', monospace; letter-spacing: 0.06em;
font-size: 13px;
font-weight: 700;
color: #58d4f0;
text-shadow: 0 0 8px rgba(88,212,240,0.35);
letter-spacing: 0.06em;
}

#hash-bar2 {
margin-top: 4px;
display: flex;
align-items: center;
gap: 12px;
flex-wrap: wrap;
font-size: 11px;
}
#hash-bar2 .label { color: #6e7681; font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; }
#session-hash { font-family: 'Consolas', 'Lucida Console', monospace; font-size: 11px; color: #6e7681; }

.hash-btn {
background: none;
border: 1px solid #21262d;
border-radius: 4px;
color: #6e7681;
cursor: pointer;
font-family: inherit;
font-size: 10px;
padding: 2px 8px;
letter-spacing: 0.05em;
transition: border-color 0.15s, color 0.15s;
}
.hash-btn:hover { border-color: #39d353; color: #39d353; }
html.light .hash-btn { border-color: #d0d7de; color: #57606a; }
html.light .hash-btn:hover { border-color: #1a7f37; color: #1a7f37; }

#status-bar {
margin-top: 8px;
display: flex;
gap: 16px;
flex-wrap: wrap;
}

.status-chip {
font-size: 11px;
padding: 2px 8px;
border-radius: 3px;
border: 1px solid;
display: inline-flex;
align-items: center;
gap: 5px;
}
.status-chip.ok    { border-color: #1a6b26; color: #39d353; }
.status-chip.warn  { border-color: #6b4a00; color: #e3b341; }
.status-chip.err   { border-color: #6b1c1c; color: #f85149; }
.status-chip.info  { border-color: #1e5a6e; color: #58d4f0; }

/* ── Layout ─────────────────────────────────────────────────────────── */
#container {
max-width: 1200px;
margin: 0 auto;
padding: 24px 32px;
display: flex;
flex-direction: column;
gap: 12px;
}

/* ── Section Cards ──────────────────────────────────────────────────── */
.section {
background: #0d1117; /* explicit dark */
border: 1px solid #21262d;
border-radius: 6px;
overflow: hidden;
transition: border-color 0.2s;
}
.section:hover { border-color: #30363d; }

.section-header {
display: flex;
align-items: center;
gap: 10px;
padding: 10px 16px;
background: #161b22; /* explicit dark */
cursor: pointer;
user-select: none;
border-bottom: 1px solid #21262d;
transition: background 0.15s;
}
.section-header:hover { background: #1c2128; }

.section-header .icon { font-size: 15px; }

.section-header .title {
font-family: 'Consolas', 'Lucida Console', monospace; letter-spacing: 0.06em;
font-size: 11px;
font-weight: 700;
letter-spacing: 0.1em;
text-transform: uppercase;
color: #58d4f0;
flex: 1;
}

.section-header .count {
font-size: 10px;
color: #6e7681;
background: #1a1f27;
padding: 1px 6px;
border-radius: 10px;
border: 1px solid #21262d;
}

.toggle-arrow {
color: #6e7681;
font-size: 10px;
transition: transform 0.2s;
}
.section.collapsed .toggle-arrow { transform: rotate(-90deg); }

.section-body {
padding: 14px 16px;
display: grid;
grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
gap: 6px 20px;
}
.section.collapsed .section-body { display: none; }

.section-body.single-col {
grid-template-columns: 1fr;
}
.section-body.two-col {
grid-template-columns: repeat(2, 1fr);
}

/* ── Data Row ────────────────────────────────────────────────────────── */
.row {
display: flex;
gap: 8px;
min-height: 22px;
align-items: flex-start;
border-bottom: 1px solid rgba(33,38,45,0.5);
padding-bottom: 3px;
}
.row:last-child { border-bottom: none; }

.row-key {
color: #6e7681;
font-size: 11px;
min-width: 200px;
flex-shrink: 0;
padding-top: 1px;
text-overflow: ellipsis;
overflow: hidden;
white-space: nowrap;
}

.row-val {
color: #c9d1d9;
font-size: 12px;
word-break: break-all;
flex: 1;
}

.row-val.green  { color: #39d353; }
.row-val.cyan   { color: #58d4f0; }
.row-val.yellow { color: #e3b341; }
.row-val.red    { color: #f85149; }
.row-val.purple { color: #bc8cff; }
.row-val.dim    { color: #6e7681; }

/* ── Tags ────────────────────────────────────────────────────────────── */
.tag {
display: inline-block;
padding: 1px 6px;
border-radius: 3px;
font-size: 10px;
margin: 1px 2px 1px 0;
border: 1px solid;
}
.tag.yes  { border-color: #1a6b26; color: #39d353; background: rgba(57,211,83,0.06); }
.tag.no   { border-color: #3d1a1a; color: #f85149; background: rgba(248,81,73,0.06); }
.tag.item { border-color: #1e5a6e; color: #58d4f0; background: rgba(88,212,240,0.06); }
.tag.warn { border-color: #6b4a00; color: #e3b341; background: rgba(227,179,65,0.06); }

/* ── Canvas preview ─────────────────────────────────────────────────── */
#canvas-preview-wrap {
grid-column: 1 / -1;
display: flex;
align-items: center;
gap: 16px;
padding: 8px 0;
border-bottom: 1px solid rgba(33,38,45,0.5);
}
#canvas-preview-wrap canvas {
border: 1px solid #21262d;
border-radius: 4px;
image-rendering: pixelated;
}

/* ── Font grid ──────────────────────────────────────────────────────── */
#font-grid {
grid-column: 1 / -1;
display: flex;
flex-wrap: wrap;
gap: 4px;
padding: 4px 0;
}

/* ── Raw block ──────────────────────────────────────────────────────── */
.raw-block {
grid-column: 1 / -1;
background: #161b22; /* explicit dark */
border: 1px solid #21262d; /* explicit border */
border-radius: 4px;
padding: 10px 12px;
font-size: 11px;
color: #6e7681;
white-space: pre-wrap;
word-break: break-all;
max-height: 300px;
overflow-y: auto;
}

/* ── Progress bar ────────────────────────────────────────────────────── */
.progress-wrap {
grid-column: 1 / -1;
margin: 4px 0;
}
.progress-label {
font-size: 11px;
color: #6e7681;
margin-bottom: 4px;
}
.progress-bar {
height: 4px;
background: #161b22; /* explicit dark */
border-radius: 2px;
overflow: hidden;
}
.progress-fill {
height: 100%;
background: linear-gradient(90deg, #39d353, #58d4f0);
transition: width 0.4s ease;
box-shadow: 0 0 6px rgba(57,211,83,0.5);
}

/* ── Scrollbar ────────────────────────────────────────────???????????????????????????????????? */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0d1117; } /* explicit dark */
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #484f58; }

/* ── Loading overlay ─────────────────────────────────────────────────── */
#loader {
position: fixed;
inset: 0;
background: #090c10; /* explicit dark */
display: flex;
flex-direction: column;
align-items: center;
justify-content: center;
gap: 16px;
z-index: 9999;
transition: opacity 0.4s ease;
}
#loader.done { opacity: 0; pointer-events: none; }

#loader h2 {
font-family: 'Consolas', 'Lucida Console', monospace; letter-spacing: 0.06em;
font-size: 14px;
color: #39d353;
letter-spacing: 0.15em;
text-shadow: 0 0 8px rgba(57,211,83,0.35);
animation: pulse 1.2s ease-in-out infinite;
}

#loader-bar { width: 260px; height: 2px; background: #1a2030; border-radius: 1px; overflow: hidden; }
#loader-fill {
height: 100%;
width: 0%;
background: linear-gradient(90deg, #39d353, #58d4f0);
transition: width 0.15s linear;
box-shadow: 0 0 8px rgba(57,211,83,0.6);
}
#loader-msg { font-size: 11px; color: #6e7681; min-height: 16px; letter-spacing: 0.05em; }

@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.6} }

/* ── Responsive ─────────────────────────────────────────────────────── */

/* ── Light Mode Variables ───────────────────────────────────────────── */
/* ── Dark mode: explicit backgrounds for intel bar & misc widgets ───── */
.intel-cell   { background: #0d1117; }
#intel-bar    { background: #161b22; }
.raw-block    { background: #161b22; }
.progress-bar { background: #161b22; }
.section-header .count { background: #0d1117; }

/* ── Dark mode: explicit text colours & borders ──────────────────────────

- WebKit fails to resolve var() in inherited colour contexts for certain
- elements (same root cause as the background-color bug).  Every colour
- that must be visible on a dark background is stated explicitly below.
- Light-mode overrides in the html.light block below take precedence via
- higher specificity — no !important required.
- ─────────────────────────────────────────────────────────────────────── */

/* Page / body */
body              { color: #c9d1d9; }

/* Masthead */
#masthead h1                { color: #39d353; text-shadow: 0 0 8px rgba(57,211,83,0.35); }
#masthead h1 span.ver       { color: #6e7681; }
#hash-bar .label            { color: #6e7681; }
#master-hash                { color: #58d4f0; text-shadow: 0 0 8px rgba(88,212,240,0.35); }
#theme-toggle               { border-color: #21262d; color: #6e7681; }
#theme-toggle:hover         { border-color: #58d4f0; color: #58d4f0; }

/* Status chips */
.status-chip.ok             { border-color: #1a6b26;  color: #39d353; }
.status-chip.warn           { border-color: #6b4a00;  color: #e3b341; }
.status-chip.err            { border-color: #6b1c1c;  color: #f85149; }
.status-chip.info           { border-color: #1e5a6e;  color: #58d4f0; }

/* Section cards */
.section                    { border-color: #21262d; }
.section-header             { border-bottom-color: #21262d; }
.section-header .title      { color: #58d4f0; }
.section-header .count      { color: #6e7681; background: #0d1117; border-color: #21262d; }
.toggle-arrow               { color: #6e7681; }
.section-header:hover       { background: #1c2128; }

/* Data rows */
.row-key                    { color: #6e7681; }
.row-val                    { color: #c9d1d9; }
.row-val.green              { color: #39d353; }
.row-val.cyan               { color: #58d4f0; }
.row-val.yellow             { color: #e3b341; }
.row-val.red                { color: #f85149; }
.row-val.purple             { color: #bc8cff; }
.row-val.dim                { color: #6e7681; }

/* Tags */
.tag.yes   { border-color: #1a6b26; color: #39d353; background: rgba(57,211,83,0.06); }
.tag.no    { border-color: #3d1a1a; color: #f85149; background: rgba(248,81,73,0.06); }
.tag.item  { border-color: #1e5a6e; color: #58d4f0; background: rgba(88,212,240,0.06); }
.tag.warn  { border-color: #6b4a00; color: #e3b341; background: rgba(227,179,65,0.06); }

/* Intelligence bar */
#intel-bar                  { border-color: #21262d; }
.intel-cell                 { border-right-color: #21262d; }
.intel-label                { color: #6e7681; }
.intel-value                { color: #c9d1d9; }
.intel-sub                  { color: #6e7681; }

/* Confidence underlines — also use explicit values (no var) */
.intel-conf.high            { background: #39d353; box-shadow: 0 0 6px rgba(57,211,83,0.4); }
.intel-conf.medium          { background: #e3b341; box-shadow: 0 0 6px rgba(227,179,65,0.35); }
.intel-conf.low             { background: #f85149; box-shadow: 0 0 6px rgba(248,81,73,0.3); }
.intel-conf.none            { background: #21262d; }

/* Misc widgets */
.raw-block                  { color: #6e7681; border-color: #21262d; }
.progress-label             { color: #6e7681; }
.progress-fill              { background: linear-gradient(90deg, #39d353, #58d4f0);
box-shadow: 0 0 6px rgba(57,211,83,0.5); }

/* Loader */
#loader h2                  { color: #39d353; text-shadow: 0 0 8px rgba(57,211,83,0.35); }
#loader-msg                 { color: #6e7681; }
#loader-fill                { background: linear-gradient(90deg, #39d353, #58d4f0);
box-shadow: 0 0 8px rgba(57,211,83,0.6); }

/* Scrollbar */
::-webkit-scrollbar-thumb   { background: #30363d; }
::-webkit-scrollbar-thumb:hover { background: #484f58; }

html.light {
--bg:        #f0f2f5;
--bg2:       #ffffff;
--bg3:       #e8eaed;
--border:    #d0d7de;
--green:     #1a7f37;
--green-dim: #b3e6c3;
--cyan:      #0969da;
--cyan-dim:  #b6d7f7;
--yellow:    #9a6700;
--red:       #cf222e;
--purple:    #8250df;
--text:      #1f2328;
--text-dim:  #57606a;
--glow:      0 0 8px rgba(26,127,55,0.2);
--glow-c:    0 0 8px rgba(9,105,218,0.2);
}

/* ── Light Mode: Explicit Element Overrides ─────────────────────────────

- Safari (WebKit) does not reliably recompute var() references when CSS
- custom properties are overridden on the html element vs :root at runtime.
- Every rule below uses a hard-coded value so no variable resolution is
- needed.  Where the base dark-mode rule used !important, we match it here.
- ─────────────────────────────────────────────────────────────────────── */

/* Page canvas */
html.light body {
background-color: #f0f2f5; /* no !important needed — base rule no longer uses it */
background-image:
radial-gradient(ellipse at 20% 0%, rgba(26,127,55,0.04) 0%, transparent 60%),
radial-gradient(ellipse at 80% 100%, rgba(9,105,218,0.03) 0%, transparent 60%);
color: #1f2328;
}

/* Header */
html.light #masthead { background: rgba(255,255,255,0.95); }
html.light #masthead h1 { color: #1a7f37; text-shadow: none; }
html.light #master-hash { color: #0969da; text-shadow: none; }
html.light #hash-bar .label { color: #57606a; }
html.light #theme-toggle { border-color: #d0d7de; color: #57606a; }

/* Section cards */
html.light .section { background: #ffffff; border-color: #d0d7de; }
html.light .section-header { background: #e8eaed; border-bottom-color: #d0d7de; }
html.light .section-header .title { color: #0969da; }
html.light .section-header .icon  { color: initial; }
html.light .toggle-arrow { color: #57606a; }
html.light .section-body { background: #ffffff; }

/* Data rows */
html.light .row { border-bottom-color: rgba(208,215,222,0.6); }
html.light .row-key            { color: #57606a; }
html.light .row-val            { color: #1f2328; }
html.light .row-val.green      { color: #1a7f37; }
html.light .row-val.cyan       { color: #0969da; }
html.light .row-val.yellow     { color: #9a6700; }
html.light .row-val.red        { color: #cf222e; }
html.light .row-val.purple     { color: #8250df; }
html.light .row-val.dim        { color: #57606a; }

/* Intelligence bar */
html.light #intel-bar    { background: #e8eaed; }
html.light .intel-cell   { background: #ffffff; }
html.light .intel-label  { color: #57606a; }
html.light .intel-value  { color: #1f2328; }
html.light .intel-sub    { color: #57606a; }
html.light .intel-conf.none { background: #d0d7de; }

/* Misc widgets */
html.light .raw-block    { background: #e8eaed; }
html.light .progress-bar { background: #e8eaed; }
html.light .progress-fill {
background: linear-gradient(90deg, #1a7f37, #0969da);
box-shadow: 0 0 6px rgba(26,127,55,0.3);
}
html.light #canvas-preview-wrap { background: transparent; }
html.light #loader-msg   { color: #57606a; }

/* Loader */
html.light #loader       { background: #f0f2f5; }
html.light #loader h2    { color: #1a7f37; text-shadow: none; }
html.light #loader-bar   { background: #d0d7de; }
html.light #loader-fill  {
background: linear-gradient(90deg, #1a7f37, #0969da);
box-shadow: 0 0 8px rgba(26,127,55,0.4);
}

html.light .section:hover { border-color: #b0b8c1; }
html.light .section-header:hover { background: #f6f8fa; }
html.light .raw-block { color: #57606a; }
html.light #masthead { background: rgba(255,255,255,0.95); }
html.light .status-chip.ok   { border-color: #b3e6c3; color: #1a7f37; }
html.light .status-chip.warn { border-color: #f5d58a; color: #9a6700; }
html.light .status-chip.err  { border-color: #ffc1be; color: #cf222e; }
html.light .status-chip.info { border-color: #b6d7f7; color: #0969da; }
html.light .tag.yes  { border-color: #b3e6c3; color: #1a7f37; background: rgba(26,127,55,0.07); }
html.light .tag.no   { border-color: #ffc1be; color: #cf222e; background: rgba(207,34,46,0.07); }
html.light .tag.item { border-color: #b6d7f7; color: #0969da; background: rgba(9,105,218,0.07); }
html.light .tag.warn { border-color: #f5d58a; color: #9a6700; background: rgba(154,103,0,0.07); }
html.light #loader   { background: #f0f2f5; }
html.light #loader h2 { color: #1a7f37; }
html.light #loader-bar { background: #d0d7de; }
html.light .section-header .count { background: #f6f8fa; }
html.light canvas { border-color: #d0d7de; }

/* ── Theme Toggle Button ─────────────────────────────────────────────── */
#theme-toggle {
background: none;
border: 1px solid #21262d;
border-radius: 4px;
color: #6e7681;
cursor: pointer;
font-family: inherit;
font-size: 12px;
padding: 4px 10px;
letter-spacing: 0.05em;
transition: border-color 0.15s, color 0.15s, background 0.15s;
white-space: nowrap;
display: flex;
align-items: center;
gap: 6px;
}
#theme-toggle:hover {
border-color: #58d4f0;
color: #58d4f0;
background: rgba(88,212,240,0.06);
}
html.light #theme-toggle:hover {
background: rgba(9,105,218,0.06);
}

/* ── Masthead top row (title + toggle on same line) ─────────────────── */
#masthead-top {
display: flex;
align-items: center;
justify-content: space-between;
gap: 12px;
}

/* ── Summary Intelligence Bar ────────────────────────────────────────── */
#intel-bar {
margin-top: 14px;
display: flex;
flex-wrap: wrap;
gap: 2px;
border: 1px solid #21262d;
border-radius: 5px;
overflow: hidden;
background: #161b22; /* explicit dark */
}

.intel-cell {
flex: 1;
min-width: 110px;
padding: 8px 12px 0 12px;
background: #0d1117; /* explicit dark */
position: relative;
display: flex;
flex-direction: column;
gap: 2px;
border-right: 1px solid #21262d;
}
.intel-cell:last-child { border-right: none; }

.intel-label {
font-size: 9px;
text-transform: uppercase;
letter-spacing: 0.12em;
color: #6e7681;
white-space: nowrap;
}

.intel-value {
font-size: 12px;
font-weight: 700;
color: #c9d1d9;
white-space: nowrap;
overflow: hidden;
text-overflow: ellipsis;
padding-bottom: 7px;
}

.intel-sub {
font-size: 9px;
color: #6e7681;
white-space: nowrap;
overflow: hidden;
text-overflow: ellipsis;
margin-top: -2px;
padding-bottom: 7px;
}

/* Confidence underline strip — sits flush at bottom of each cell */
.intel-conf {
position: absolute;
bottom: 0;
left: 0;
right: 0;
height: 3px;
border-radius: 0 0 1px 1px;
}
.intel-conf.high   { background: #39d353;  box-shadow: 0 0 6px rgba(57,211,83,0.4); }
.intel-conf.medium { background: #e3b341;  box-shadow: 0 0 6px rgba(227,179,65,0.35); }
.intel-conf.low    { background: #f85149;     box-shadow: 0 0 6px rgba(248,81,73,0.3); }
.intel-conf.none   { background: #21262d;  }

html.light .intel-conf.high   { box-shadow: 0 0 4px rgba(26,127,55,0.3); }
html.light .intel-conf.medium { box-shadow: 0 0 4px rgba(154,103,0,0.3); }
html.light .intel-conf.low    { box-shadow: 0 0 4px rgba(207,34,46,0.25); }

@media (max-width: 900px) {
.intel-cell { min-width: 90px; }
.intel-value { font-size: 11px; }
}
@media (max-width: 600px) {
#intel-bar { flex-direction: column; }
.intel-cell { border-right: none; border-bottom: 1px solid #21262d; }
.intel-cell:last-child { border-bottom: none; }
.intel-conf { bottom: 0; height: 3px; }
}

/* ── Responsive: Intel Bar ──────────────────────────────────────────── */

/*

- PORTRAIT PHONES (≤ 600px wide)
- Render intel cells as a 2-column grid so the bar is roughly half
- the height it would be in a single-column stack.
- Masthead is de-stickied so it doesn't eat the viewport.
  */
  @media (max-width: 600px) and (orientation: portrait) {
  #masthead {
  position: relative;  /* not sticky — prevents full-viewport lockout */
  padding: 12px 14px 10px;
  }
  #masthead h1 { font-size: 15px; }
  #masthead h1 span.ver { display: none; } /* hide version line — reclaim space */

```
#intel-bar {
  display: grid;
  grid-template-columns: 1fr 1fr;
  overflow: visible;
  margin-top: 10px;
}
.intel-cell {
  border-right: 1px solid #21262d;
  border-bottom: 1px solid #21262d;
  min-width: 0;
  padding: 6px 8px 0 8px;
}
/* Even cells lose the right border (they're in col 2) */
.intel-cell:nth-child(even) { border-right: none; }
/* If total cells are even, last two lose bottom border */
.intel-cell:nth-last-child(-n+2) { border-bottom: none; }
/* If odd total, last lone item spans both columns */
.intel-cell:last-child:nth-child(odd) {
  grid-column: 1 / -1;
  border-right: none;
  border-bottom: none;
}

.intel-label {
  font-size: 7.5px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.intel-value { font-size: 11px; padding-bottom: 6px; }
.intel-sub   { font-size: 8px;  padding-bottom: 6px; }
.intel-conf  { height: 2px; }

#hash-bar    { margin-top: 8px; }
#master-hash { font-size: 11px; }
#status-bar  { gap: 8px; }
.status-chip { font-size: 10px; padding: 1px 6px; }
```

}

/*

- LANDSCAPE PHONES / SMALL TABLETS (≤ 900px, landscape)
- Render intel cells as a single horizontally-scrollable strip.
- Cells don't wrap — user swipes to see all 10.
- Prevents “OPERATING SYSTEM” and “ARCHITECTURE” label stomp.
  */
  @media (max-width: 900px) and (orientation: landscape) {
  #masthead { padding: 8px 16px; }
  #masthead h1 { font-size: 14px; }
  #masthead h1 span.ver { font-size: 9px; }

```
#intel-bar {
  flex-wrap: nowrap;
  overflow-x: auto;
  overflow-y: visible;
  -webkit-overflow-scrolling: touch; /* iOS momentum scroll */
  scrollbar-width: thin;
  scrollbar-color: #21262d transparent;
  margin-top: 8px;
  /* Subtle right fade to hint at scrollability */
  -webkit-mask-image: linear-gradient(to right, black 85%, transparent 100%);
          mask-image: linear-gradient(to right, black 85%, transparent 100%);
}
.intel-cell {
  flex: 0 0 auto;    /* prevent shrinking */
  min-width: 88px;
  max-width: 120px;
  padding: 5px 10px 0 10px;
}
.intel-label {
  font-size: 7.5px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.intel-value { font-size: 11px; padding-bottom: 5px; }
.intel-sub   { font-size: 8px;  padding-bottom: 5px; }
.intel-conf  { height: 2px; }

#hash-bar   { margin-top: 6px; }
#status-bar { margin-top: 4px; gap: 8px; }
.status-chip { font-size: 10px; }
```

}

/* ── General small-screen section body / layout ─────────────────────── */
@media (max-width: 768px) {
#container { padding: 12px 16px; }
.section-body { grid-template-columns: 1fr; }
.row-key { min-width: 140px; }
}

</style>
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
      <span class="ver">v4.1 // intranet only // solarian design</span>
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
// Server-side payload — injected by PHP; defined before assets/browserprint.js
// executes (this classic inline script always runs before deferred scripts).
const PHP_DATA = <?php echo $php_payload; ?> || {};
</script>
<script src="assets/browserprint.core.js" defer></script>
<script src="assets/browserprint.app.js" defer></script>

</body>
</html>
