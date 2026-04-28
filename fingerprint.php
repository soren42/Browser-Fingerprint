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
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

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
–bg:        #090c10;
–bg2:       #0d1117;
–bg3:       #161b22;
–border:    #21262d;
–green:     #39d353;
–green-dim: #1a6b26;
–cyan:      #58d4f0;
–cyan-dim:  #1e5a6e;
–yellow:    #e3b341;
–red:       #f85149;
–purple:    #bc8cff;
–text:      #c9d1d9;
–text-dim:  #6e7681;
–glow:      0 0 8px rgba(57,211,83,0.35);
–glow-c:    0 0 8px rgba(88,212,240,0.35);
}

/* ── Reset & Base ───────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; }

body {
background-color: #090c10; /* explicit — no var(), no !important (WebKit shorthand+var+!important bug) */
color: #c9d1d9;
font-family: ‘Consolas’, ‘Fira Code’, ‘Courier New’, monospace;
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
backdrop-filter: blur(8px);
}

#masthead h1 {
font-family: ‘Consolas’, ‘Lucida Console’, monospace; letter-spacing: 0.06em;
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
font-family: ‘Consolas’, ‘Courier New’, monospace;
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
font-family: ‘Consolas’, ‘Lucida Console’, monospace; letter-spacing: 0.06em;
font-size: 13px;
font-weight: 700;
color: #58d4f0;
text-shadow: 0 0 8px rgba(88,212,240,0.35);
letter-spacing: 0.06em;
}

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
font-family: ‘Consolas’, ‘Lucida Console’, monospace; letter-spacing: 0.06em;
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

/* ── Scrollbar ──────────────────────────────────────────────────────── */
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
font-family: ‘Consolas’, ‘Lucida Console’, monospace; letter-spacing: 0.06em;
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
–bg:        #f0f2f5;
–bg2:       #ffffff;
–bg3:       #e8eaed;
–border:    #d0d7de;
–green:     #1a7f37;
–green-dim: #b3e6c3;
–cyan:      #0969da;
–cyan-dim:  #b6d7f7;
–yellow:    #9a6700;
–red:       #cf222e;
–purple:    #8250df;
–text:      #1f2328;
–text-dim:  #57606a;
–glow:      0 0 8px rgba(26,127,55,0.2);
–glow-c:    0 0 8px rgba(9,105,218,0.2);
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
- Masthead is de-stickied so it doesn’t eat the viewport.
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
- Cells don’t wrap — user swipes to see all 10.
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
      <span class="ver">v3.7 // intranet only // solarian design</span>
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
    <span id="entropy-score"></span>
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
'use strict';

/* ═══════════════════════════════════════════════════════════════════════════
   UTILITIES
═══════════════════════════════════════════════════════════════════════════ */

// FNV-1a 32-bit hash → hex string
function fnv32a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return ('00000000' + h.toString(16)).slice(-8).toUpperCase();
}

// MurmurHash3-inspired 32-bit
function murmurhash3(str) {
  let h = 0xdeadbeef;
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    c = ((c >> 16) ^ c) * 0x45d9f3b;
    c = ((c >> 16) ^ c) * 0x45d9f3b;
    c = (c >> 16) ^ c;
    h ^= c;
    h = (h << 5) + h + c;
    h = h & h;
  }
  return ('00000000' + (h >>> 0).toString(16)).slice(-8).toUpperCase();
}

// Combine multiple hash inputs into one master hash
function masterHash(parts) {
  return fnv32a(parts.join('|')) + '-' + murmurhash3(parts.join('~'));
}

// Render rows into a section body
function renderRows(bodyId, rows, countId) {
  const body = document.getElementById(bodyId);
  body.innerHTML = '';
  rows.forEach(([key, val, cls]) => {
    const row = document.createElement('div');
    row.className = 'row';
    const k = document.createElement('span');
    k.className = 'row-key';
    k.textContent = key;
    const v = document.createElement('span');
    v.className = 'row-val' + (cls ? ' ' + cls : '');
    v.innerHTML = val;
    row.appendChild(k);
    row.appendChild(v);
    body.appendChild(row);
  });
  if (countId) document.getElementById(countId).textContent = rows.length;
}

function appendRow(bodyId, key, val, cls) {
  const body = document.getElementById(bodyId);
  const row = document.createElement('div');
  row.className = 'row';
  const k = document.createElement('span'); k.className = 'row-key'; k.textContent = key;
  const v = document.createElement('span'); v.className = 'row-val' + (cls ? ' ' + cls : ''); v.innerHTML = val;
  row.appendChild(k); row.appendChild(v);
  body.appendChild(row);
  const cnt = document.getElementById(bodyId.replace('body-','cnt-'));
  if (cnt) cnt.textContent = body.querySelectorAll('.row').length;
}

function tag(text, cls) {
  return `<span class="tag ${cls}">${text}</span>`;
}
function yesno(b) { return b ? tag('YES','yes') : tag('NO','no'); }

function addStatusChip(text, cls) {
  const bar = document.getElementById('status-bar');
  bar.innerHTML += `<span class="status-chip ${cls}">${text}</span>`;
}

// Section collapse toggle
function toggleSection(id) {
  document.getElementById(id).classList.toggle('collapsed');
}

/* ═══════════════════════════════════════════════════════════════════════════
   LOADING PROGRESS
═══════════════════════════════════════════════════════════════════════════ */
let loadProgress = 0;
function setProgress(pct, msg) {
  loadProgress = pct;
  document.getElementById('loader-fill').style.width = pct + '%';
  if (msg) document.getElementById('loader-msg').textContent = msg;
}

/* ═══════════════════════════════════════════════════════════════════════════
   PHP PAYLOAD (server-side data)
═══════════════════════════════════════════════════════════════════════════ */
const PHP_DATA = <?php echo $php_payload; ?>;

/* ═══════════════════════════════════════════════════════════════════════════
   MASTER FINGERPRINT ACCUMULATOR
═══════════════════════════════════════════════════════════════════════════ */
const FP = {};

/* ═══════════════════════════════════════════════════════════════════════════
   §1  SYSTEM IDENTITY
═══════════════════════════════════════════════════════════════════════════ */
async function collectIdentity() {
  setProgress(5, 'Collecting system identity...');
  const nav = navigator;
  const rows = [];

  // Basic UA
  rows.push(['userAgent',              nav.userAgent,                        'cyan']);
  rows.push(['platform',               nav.platform || '(empty)',            'yellow']);
  rows.push(['vendor',                 nav.vendor || '(empty)',              '']);
  rows.push(['vendorSub',              nav.vendorSub || '(empty)',           '']);
  rows.push(['product',                nav.product || '(empty)',             '']);
  rows.push(['productSub',             nav.productSub || '(empty)',          '']);
  rows.push(['appName',                nav.appName || '(empty)',             '']);
  rows.push(['appCodeName',            nav.appCodeName || '(empty)',         '']);
  rows.push(['appVersion',             nav.appVersion ? nav.appVersion.substring(0,80)+'…' : '(empty)', '']);
  rows.push(['oscpu',                  nav.oscpu || '(not exposed)',         '']);
  rows.push(['buildID',                nav.buildID || '(not exposed)',       '']);
  rows.push(['pdfViewerEnabled',       yesno(nav.pdfViewerEnabled),          '']);
  rows.push(['cookieEnabled',          yesno(nav.cookieEnabled),             '']);
  rows.push(['doNotTrack',             nav.doNotTrack ?? '(not set)',        nav.doNotTrack === '1' ? 'yellow' : '']);
  rows.push(['globalPrivacyControl',   nav.globalPrivacyControl != null ? String(nav.globalPrivacyControl) : '(not set)', '']);
  rows.push(['webdriver',              yesno(nav.webdriver),                 nav.webdriver ? 'red' : '']);
  rows.push(['onLine',                 yesno(nav.onLine),                   '']);
  rows.push(['hardwareConcurrency',    String(nav.hardwareConcurrency || 0), 'green']);
  rows.push(['deviceMemory (GB)',      nav.deviceMemory != null ? nav.deviceMemory + ' GB' : '(not exposed)', 'green']);
  rows.push(['maxTouchPoints',         String(nav.maxTouchPoints || 0),      '']);
  rows.push(['language',               nav.language || '—',                 '']);
  rows.push(['languages',              (nav.languages||[]).join(', ')||'—', '']);
  rows.push(['plugins count',          String((nav.plugins||{length:0}).length), '']);

  // Plugins list
  if (nav.plugins && nav.plugins.length) {
    const plugList = Array.from(nav.plugins).map(p=>p.name).join('<br>');
    rows.push(['plugins list', plugList, 'dim']);
  }

  // MimeTypes
  rows.push(['mimeTypes count', String((nav.mimeTypes||{length:0}).length), '']);

  // Keyboard
  if (nav.keyboard) {
    try {
      const layout = await nav.keyboard.getLayoutMap();
      rows.push(['keyboard layout entries', String(layout.size), 'cyan']);
      const sample = [];
      layout.forEach((v,k) => sample.push(k+'→'+v));
      rows.push(['keyboard sample (first 10)', sample.slice(0,10).join(', '), 'dim']);
    } catch(e) {
      rows.push(['keyboard layout', '(access denied: '+e.message+')', 'dim']);
    }
  } else {
    rows.push(['keyboard API', '(not available)', 'dim']);
  }

  // User-Agent Client Hints
  if (nav.userAgentData) {
    const uad = nav.userAgentData;
    rows.push(['UAData.platform',   uad.platform || '—', 'purple']);
    rows.push(['UAData.mobile',     yesno(uad.mobile), '']);
    const brands = (uad.brands||[]).map(b=>b.brand+'@'+b.version).join(', ');
    rows.push(['UAData.brands',     brands || '—', 'purple']);
    try {
      const hints = await uad.getHighEntropyValues([
        'architecture','bitness','model','platform','platformVersion',
        'uaFullVersion','fullVersionList','wow64'
      ]);
      rows.push(['CH: architecture',    hints.architecture || '—', 'purple']);
      rows.push(['CH: bitness',         hints.bitness || '—', 'purple']);
      rows.push(['CH: model',           hints.model || '—', 'purple']);
      rows.push(['CH: platform',        hints.platform || '—', 'purple']);
      rows.push(['CH: platformVersion', hints.platformVersion || '—', 'purple']);
      rows.push(['CH: uaFullVersion',   hints.uaFullVersion || '—', 'purple']);
      rows.push(['CH: wow64',           hints.wow64 != null ? String(hints.wow64) : '—', 'purple']);
      const fvl = (hints.fullVersionList||[]).map(b=>b.brand+'@'+b.version).join(', ');
      rows.push(['CH: fullVersionList', fvl || '—', 'purple']);
      FP.uaCH = JSON.stringify(hints);
    } catch(e) {
      rows.push(['UA-CH getHighEntropyValues', '(failed: '+e.message+')', 'red']);
    }
  } else {
    rows.push(['UA-CH API', '(not available — not Chromium?)', 'dim']);
  }

  FP.userAgent = nav.userAgent;
  FP.platform  = nav.platform || '';
  FP.languages = (nav.languages||[]).join(',');
  FP.hw_concurrency = String(nav.hardwareConcurrency||0);
  FP.device_memory  = String(nav.deviceMemory||'?');

  renderRows('body-identity', rows, 'cnt-identity');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §2  HTTP HEADERS (PHP)
═══════════════════════════════════════════════════════════════════════════ */
function collectHeaders() {
  setProgress(12, 'Parsing HTTP headers...');
  const rows = [];

  // PHP-collected HTTP headers
  const h = PHP_DATA.headers || {};
  Object.entries(h).forEach(([k,v]) => rows.push([k, String(v), '']));

  // Key server vars
  const s = PHP_DATA.server || {};
  const svKeys = ['REMOTE_ADDR','HTTP_X_FORWARDED_FOR','HTTP_X_REAL_IP',
    'SERVER_PROTOCOL','SERVER_SOFTWARE','REQUEST_METHOD','REQUEST_URI',
    'HTTP_HOST','HTTPS','SERVER_PORT','GATEWAY_INTERFACE','PHP_SELF'];
  svKeys.forEach(k => {
    if (s[k]) rows.push(['[SERVER] '+k, String(s[k]), 'yellow']);
  });

  rows.push(['PHP version',   PHP_DATA.php_version, 'green']);
  rows.push(['PHP OS',        PHP_DATA.php_os, '']);
  rows.push(['PHP SAPI',      PHP_DATA.php_sapi, '']);
  rows.push(['PHP INT_SIZE',  String(PHP_DATA.php_int_size)+'B (' + (PHP_DATA.php_int_size*8) + '-bit)', '']);
  rows.push(['Collection time (UTC)', PHP_DATA.timestamp_utc, 'dim']);

  FP.remoteAddr = PHP_DATA.remote_addr || '';
  renderRows('body-headers', rows, 'cnt-headers');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §3  DISPLAY & SCREEN
═══════════════════════════════════════════════════════════════════════════ */
function collectScreen() {
  setProgress(20, 'Measuring display geometry...');
  const sc = screen;
  const rows = [
    ['screen.width',           sc.width + ' px', 'cyan'],
    ['screen.height',          sc.height + ' px', 'cyan'],
    ['screen.availWidth',      sc.availWidth + ' px', ''],
    ['screen.availHeight',     sc.availHeight + ' px', ''],
    ['screen.availLeft',       sc.availLeft + ' px', ''],
    ['screen.availTop',        sc.availTop + ' px', ''],
    ['screen.colorDepth',      sc.colorDepth + ' bits', 'green'],
    ['screen.pixelDepth',      sc.pixelDepth + ' bits', ''],
    ['window.devicePixelRatio',String(window.devicePixelRatio), 'yellow'],
    ['window.innerWidth',      window.innerWidth + ' px', ''],
    ['window.innerHeight',     window.innerHeight + ' px', ''],
    ['window.outerWidth',      window.outerWidth + ' px', ''],
    ['window.outerHeight',     window.outerHeight + ' px', ''],
    ['window.screenX',         window.screenX + ' px', ''],
    ['window.screenY',         window.screenY + ' px', ''],
    ['window.scrollX',         window.scrollX + ' px', ''],
    ['window.scrollY',         window.scrollY + ' px', ''],
    ['document.visibilityState', document.visibilityState, ''],
  ];

  // orientation
  if (sc.orientation) {
    rows.push(['screen.orientation.type',  sc.orientation.type, '']);
    rows.push(['screen.orientation.angle', sc.orientation.angle + '°', '']);
  }

  // matchMedia DPI probes
  const dpiTests = [72,96,120,144,192,240,300,360];
  let detectedDpi = 'unknown';
  dpiTests.forEach(d => {
    if (window.matchMedia(`(min-resolution: ${d}dpi)`).matches) detectedDpi = '>= ' + d;
  });
  rows.push(['Approx. screen DPI', detectedDpi, 'yellow']);

  // Physical size estimate
  const physW = Math.round(sc.width / window.devicePixelRatio);
  const physH = Math.round(sc.height / window.devicePixelRatio);
  rows.push(['Logical resolution', physW + ' × ' + physH + ' (CSS px)', '']);

  FP.screen = `${sc.width}x${sc.height}x${sc.colorDepth}@${window.devicePixelRatio}`;
  renderRows('body-screen', rows, 'cnt-screen');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §4  CANVAS 2D FINGERPRINT
═══════════════════════════════════════════════════════════════════════════ */
function collectCanvas() {
  setProgress(28, 'Rendering canvas fingerprint...');
  const body = document.getElementById('body-canvas');
  body.innerHTML = '';

  // ── Visible canvas preview ───────────────────────────────────────────
  const previewWrap = document.createElement('div');
  previewWrap.id = 'canvas-preview-wrap';

  const canvas = document.createElement('canvas');
  canvas.width  = 400;
  canvas.height = 120;
  const ctx = canvas.getContext('2d');

  // Background
  ctx.fillStyle = '#1a1a2e';
  ctx.fillRect(0, 0, 400, 120);

  // Gradient text
  const grad = ctx.createLinearGradient(0, 0, 400, 0);
  grad.addColorStop(0, '#39d353'); grad.addColorStop(0.5, '#58d4f0'); grad.addColorStop(1, '#bc8cff');
  ctx.fillStyle = grad;
  ctx.font = 'bold 18px Arial, sans-serif';
  ctx.fillText('BrowserPrint FP Canvas Test', 12, 30);

  // Unicode + emoji
  ctx.font = '14px Georgia, serif';
  ctx.fillStyle = '#e3b341';
  ctx.fillText('Ω ℕ ∆ π ∑ √ ≈ ≠ • ← → ↑ ↓ ★ ♠ ♣ ♥ ♦', 12, 55);

  // Mixed fonts
  ctx.font = 'italic 12px Times New Roman, serif';
  ctx.fillStyle = '#c9d1d9';
  ctx.fillText('The quick brown fox jumps over the lazy dog. 0123456789', 12, 75);

  // Shapes
  ctx.fillStyle = 'rgba(88,212,240,0.5)';
  ctx.beginPath(); ctx.arc(360, 60, 25, 0, Math.PI*2); ctx.fill();

  ctx.fillStyle = 'rgba(188,140,255,0.4)';
  ctx.fillRect(310, 30, 35, 55);

  ctx.strokeStyle = '#f85149';
  ctx.lineWidth = 2;
  ctx.beginPath(); ctx.moveTo(290, 20); ctx.lineTo(380, 100); ctx.stroke();

  // Sub-pixel rendering test
  ctx.font = '11.3px Arial';
  ctx.fillStyle = '#ffffff';
  ctx.fillText('Subpixel: 1.33 2.67 3.14', 12, 100);

  // Shadows
  ctx.shadowColor = 'rgba(57,211,83,0.8)';
  ctx.shadowBlur = 8;
  ctx.fillStyle = '#39d353';
  ctx.fillText('SHADOW', 12, 115);
  ctx.shadowBlur = 0;

  const dataURL = canvas.toDataURL('image/png');
  const hash = fnv32a(dataURL) + '-' + murmurhash3(dataURL);

  const info = document.createElement('div');
  info.innerHTML = `
    <div class="row"><span class="row-key">Canvas hash (FNV32a+MH3)</span><span class="row-val cyan">${hash}</span></div>
    <div class="row"><span class="row-key">dataURL length</span><span class="row-val">${dataURL.length} chars</span></div>
    <div class="row"><span class="row-key">toDataURL format</span><span class="row-val">image/png</span></div>
  `;
  previewWrap.appendChild(canvas);
  previewWrap.appendChild(info);
  body.appendChild(previewWrap);

  // ── JPEG variant ─────────────────────────────────────────────────────
  const jpegURL = canvas.toDataURL('image/jpeg', 0.9);
  const jpegHash = fnv32a(jpegURL);
  const r2 = document.createElement('div'); r2.className='row';
  r2.innerHTML = `<span class="row-key">JPEG hash (q=0.9)</span><span class="row-val cyan">${jpegHash}</span>`;
  body.appendChild(r2);

  const r3 = document.createElement('div'); r3.className='row';
  r3.innerHTML = `<span class="row-key">JPEG dataURL length</span><span class="row-val">${jpegURL.length} chars</span>`;
  body.appendChild(r3);

  // ── Pixel-perfect sample ─────────────────────────────────────────────
  const id = ctx.getImageData(0, 0, 10, 1);
  const pixHex = Array.from(id.data).slice(0,40).map(x=>x.toString(16).padStart(2,'0')).join(' ');
  const r4 = document.createElement('div'); r4.className='row';
  r4.innerHTML = `<span class="row-key">Pixel sample [0,0..9,0] RGBA</span><span class="row-val dim" style="font-size:10px">${pixHex}</span>`;
  body.appendChild(r4);

  document.getElementById('cnt-canvas').textContent = '4';
  FP.canvas = hash;
}

/* ═══════════════════════════════════════════════════════════════════════════
   §5  WEBGL / GPU
═══════════════════════════════════════════════════════════════════════════ */
function collectWebGL() {
  setProgress(36, 'Probing WebGL/GPU surface...');
  const rows = [];

  function probeGL(contextType) {
    const c = document.createElement('canvas');
    const gl = c.getContext(contextType, {failIfMajorPerformanceCaveat: false});
    if (!gl) return null;
    return gl;
  }

  // ── WebGL1 ───────────────────────────────────────────────────────────
  const gl1 = probeGL('webgl') || probeGL('experimental-webgl');
  if (gl1) {
    rows.push(['WebGL1', 'Available', 'green']);

    // Debug renderer info
    const dbg = gl1.getExtension('WEBGL_debug_renderer_info');
    if (dbg) {
      const uRenderer = gl1.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
      const uVendor   = gl1.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
      rows.push(['GPU Renderer (unmasked)', uRenderer, 'yellow']);
      rows.push(['GPU Vendor (unmasked)',   uVendor, 'yellow']);
      FP.gpuRenderer = uRenderer;
      FP.gpuVendor   = uVendor;
    }

    rows.push(['RENDERER',               gl1.getParameter(gl1.RENDERER), '']);
    rows.push(['VENDOR',                 gl1.getParameter(gl1.VENDOR), '']);
    rows.push(['VERSION',                gl1.getParameter(gl1.VERSION), 'cyan']);
    rows.push(['SHADING_LANGUAGE_VER',   gl1.getParameter(gl1.SHADING_LANGUAGE_VERSION), '']);
    rows.push(['MAX_TEXTURE_SIZE',       gl1.getParameter(gl1.MAX_TEXTURE_SIZE) + ' px', '']);
    rows.push(['MAX_VIEWPORT_DIMS',      gl1.getParameter(gl1.MAX_VIEWPORT_DIMS).join(' × ') + ' px', '']);
    rows.push(['MAX_VERTEX_ATTRIBS',     String(gl1.getParameter(gl1.MAX_VERTEX_ATTRIBS)), '']);
    rows.push(['MAX_VERTEX_TEXTURE_IMAGE_UNITS', String(gl1.getParameter(gl1.MAX_VERTEX_TEXTURE_IMAGE_UNITS)), '']);
    rows.push(['MAX_FRAGMENT_UNIFORM_VECTORS', String(gl1.getParameter(gl1.MAX_FRAGMENT_UNIFORM_VECTORS)), '']);
    rows.push(['MAX_VERTEX_UNIFORM_VECTORS',   String(gl1.getParameter(gl1.MAX_VERTEX_UNIFORM_VECTORS)), '']);
    rows.push(['MAX_RENDERBUFFER_SIZE',  String(gl1.getParameter(gl1.MAX_RENDERBUFFER_SIZE)), '']);
    rows.push(['ALPHA_BITS',             String(gl1.getParameter(gl1.ALPHA_BITS)), '']);
    rows.push(['DEPTH_BITS',             String(gl1.getParameter(gl1.DEPTH_BITS)), '']);
    rows.push(['STENCIL_BITS',           String(gl1.getParameter(gl1.STENCIL_BITS)), '']);
    rows.push(['ANTIALIAS',              String(gl1.getContextAttributes()?.antialias), '']);

    // Shader precision
    const prec = gl1.getShaderPrecisionFormat(gl1.FRAGMENT_SHADER, gl1.HIGH_FLOAT);
    if (prec) rows.push(['FRAGMENT HIGH_FLOAT precision', `range:${prec.rangeMin}..${prec.rangeMax} precision:${prec.precision}`, '']);

    const ext1 = gl1.getSupportedExtensions() || [];
    rows.push(['WebGL1 extensions count', String(ext1.length), 'green']);
    rows.push(['WebGL1 extensions', ext1.map(e=>`<span class="tag item">${e}</span>`).join(''), '']);
    FP.webgl1ExtCount = String(ext1.length);

    // Canvas fingerprint via WebGL
    const wc = document.createElement('canvas');
    wc.width = 256; wc.height = 256;
    const wgl = wc.getContext('webgl') || wc.getContext('experimental-webgl');
    if (wgl) {
      const vsrc = `attribute vec2 p;void main(){gl_Position=vec4(p,0.0,1.0);}`;
      const fsrc = `precision mediump float;void main(){gl_FragColor=vec4(0.3,0.8,0.2,1.0);}`;
      const vs = wgl.createShader(wgl.VERTEX_SHADER);
      wgl.shaderSource(vs,vsrc); wgl.compileShader(vs);
      const fs = wgl.createShader(wgl.FRAGMENT_SHADER);
      wgl.shaderSource(fs,fsrc); wgl.compileShader(fs);
      const prog = wgl.createProgram();
      wgl.attachShader(prog,vs); wgl.attachShader(prog,fs); wgl.linkProgram(prog);
      wgl.useProgram(prog);
      const buf = wgl.createBuffer();
      wgl.bindBuffer(wgl.ARRAY_BUFFER,buf);
      wgl.bufferData(wgl.ARRAY_BUFFER, new Float32Array([-0.5,-0.5,0.5,-0.5,0.0,0.5]), wgl.STATIC_DRAW);
      const loc = wgl.getAttribLocation(prog,'p');
      wgl.enableVertexAttribArray(loc);
      wgl.vertexAttribPointer(loc,2,wgl.FLOAT,false,0,0);
      wgl.clearColor(0,0,0,1); wgl.clear(wgl.COLOR_BUFFER_BIT);
      wgl.drawArrays(wgl.TRIANGLES,0,3);
      const px = new Uint8Array(wgl.drawingBufferWidth*wgl.drawingBufferHeight*4);
      wgl.readPixels(0,0,wgl.drawingBufferWidth,wgl.drawingBufferHeight,wgl.RGBA,wgl.UNSIGNED_BYTE,px);
      const wglHash = fnv32a(Array.from(px.slice(0,256)).join(','));
      rows.push(['WebGL render hash', wglHash, 'cyan']);
      FP.webglRender = wglHash;
    }
  } else {
    rows.push(['WebGL1', 'NOT available', 'red']);
  }

  // ── WebGL2 ───────────────────────────────────────────────────────────
  const gl2 = probeGL('webgl2');
  if (gl2) {
    rows.push(['WebGL2', 'Available', 'green']);
    rows.push(['WebGL2 VERSION', gl2.getParameter(gl2.VERSION), 'cyan']);
    rows.push(['MAX_3D_TEXTURE_SIZE', String(gl2.getParameter(gl2.MAX_3D_TEXTURE_SIZE)), '']);
    rows.push(['MAX_DRAW_BUFFERS',    String(gl2.getParameter(gl2.MAX_DRAW_BUFFERS)), '']);
    rows.push(['MAX_SAMPLES',         String(gl2.getParameter(gl2.MAX_SAMPLES)), '']);
    const ext2 = gl2.getSupportedExtensions() || [];
    rows.push(['WebGL2 extensions count', String(ext2.length), '']);
  } else {
    rows.push(['WebGL2', 'NOT available', 'warn']);
  }

  // ── WebGPU (if available) ─────────────────────────────────────────────
  if (navigator.gpu) {
    rows.push(['WebGPU API', 'Present (navigator.gpu exists)', 'green']);
    navigator.gpu.requestAdapter().then(adapter => {
      if (adapter) {
        const info = adapter.info || {};
        appendRow('body-webgl', 'WebGPU adapter.vendor',       info.vendor       || '(not exposed)', 'purple');
        appendRow('body-webgl', 'WebGPU adapter.architecture', info.architecture || '(not exposed)', 'purple');
        appendRow('body-webgl', 'WebGPU adapter.device',       info.device       || '(not exposed)', 'purple');
        appendRow('body-webgl', 'WebGPU adapter.description',  info.description  || '(not exposed)', 'purple');
      } else {
        appendRow('body-webgl', 'WebGPU adapter', '(null — no capable adapter)', 'dim');
      }
    }).catch(()=>{});
  } else {
    rows.push(['WebGPU API', 'NOT available', 'dim']);
  }

  renderRows('body-webgl', rows, 'cnt-webgl');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §6  AUDIO FINGERPRINT
═══════════════════════════════════════════════════════════════════════════ */
function collectAudio() {
  setProgress(44, 'Computing audio fingerprint...');
  return new Promise(resolve => {
    const rows = [];
    try {
      const AudioCtx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
      if (!AudioCtx) throw new Error('OfflineAudioContext not available');

      const ctx = new AudioCtx(1, 4096, 44100);

      // Oscillator
      const osc = ctx.createOscillator();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(10000, ctx.currentTime);

      // Compressor
      const comp = ctx.createDynamicsCompressor();
      comp.threshold.setValueAtTime(-50, ctx.currentTime);
      comp.knee.setValueAtTime(40, ctx.currentTime);
      comp.ratio.setValueAtTime(12, ctx.currentTime);
      comp.attack.setValueAtTime(0, ctx.currentTime);
      comp.release.setValueAtTime(0.25, ctx.currentTime);

      // Biquad filter
      const filt = ctx.createBiquadFilter();
      filt.type = 'highpass';
      filt.frequency.setValueAtTime(500, ctx.currentTime);

      osc.connect(comp);
      comp.connect(filt);
      filt.connect(ctx.destination);
      osc.start(0);

      ctx.startRendering().then(buffer => {
        const data   = buffer.getChannelData(0);
        let sum      = 0;
        let peak     = 0;
        const sample = [];
        for (let i = 0; i < data.length; i++) {
          const abs = Math.abs(data[i]);
          sum += abs;
          if (abs > peak) peak = abs;
          if (i < 32) sample.push(data[i].toFixed(10));
        }
        const avg   = sum / data.length;
        const hashIn = sample.join(',');
        const audioHash = fnv32a(hashIn) + '-' + murmurhash3(hashIn);

        rows.push(['Audio hash (FNV32a+MH3)', audioHash, 'cyan']);
        rows.push(['Sample rate',             String(buffer.sampleRate) + ' Hz', '']);
        rows.push(['Buffer length',           String(buffer.length) + ' frames', '']);
        rows.push(['Channels',                String(buffer.numberOfChannels), '']);
        rows.push(['Peak amplitude',          peak.toFixed(12), 'yellow']);
        rows.push(['Average amplitude',       avg.toFixed(12), '']);
        rows.push(['First 8 samples', sample.slice(0,8).join(', '), 'dim']);

        // Context properties
        rows.push(['sampleRate',              String(ctx.sampleRate), '']);
        rows.push(['baseLatency',             ctx.baseLatency != null ? ctx.baseLatency.toFixed(6)+'s' : '(N/A)', '']);

        FP.audio = audioHash;
        renderRows('body-audio', rows, 'cnt-audio');
        resolve();
      }).catch(e => {
        rows.push(['Audio render error', e.message, 'red']);
        renderRows('body-audio', rows, 'cnt-audio');
        resolve();
      });
    } catch(e) {
      rows.push(['Audio fingerprint', 'FAILED: ' + e.message, 'red']);
      renderRows('body-audio', rows, 'cnt-audio');
      resolve();
    }
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   §7  FONT DETECTION (via Canvas measureText)
═══════════════════════════════════════════════════════════════════════════ */
function collectFonts() {
  setProgress(52, 'Enumerating installed fonts...');

  const fontList = [
    // Windows / Office
    'Arial','Arial Black','Arial Narrow','Arial Rounded MT Bold',
    'Bahnschrift','Calibri','Cambria','Cambria Math','Candara',
    'Comic Sans MS','Consolas','Constantia','Corbel','Courier New',
    'Ebrima','Franklin Gothic Medium','Gabriola','Gadugi','Georgia',
    'HoloLens MDL2 Assets','Impact','Ink Free','Javanese Text','Leelawadee UI',
    'Lucida Console','Lucida Sans Unicode','Malgun Gothic','Marlett',
    'Microsoft Himalaya','Microsoft JhengHei','Microsoft New Tai Lue',
    'Microsoft PhagsPa','Microsoft Sans Serif','Microsoft Tai Le',
    'Microsoft Uighur','Microsoft YaHei','Microsoft Yi Baiti',
    'MingLiU-ExtB','Mongolian Baiti','MS Gothic','MS PGothic',
    'MS UI Gothic','MV Boli','Myanmar Text','Nirmala UI','Palatino Linotype',
    'Segoe MDL2 Assets','Segoe Print','Segoe Script','Segoe UI',
    'Segoe UI Black','Segoe UI Emoji','Segoe UI Historic','Segoe UI Symbol',
    'SimSun','Sitka','Sylfaen','Symbol','Tahoma','Times New Roman',
    'Trebuchet MS','Verdana','Webdings','Wingdings','Yu Gothic',
    // macOS / iOS
    'American Typewriter','Andale Mono','Apple Braille','Apple Chancery',
    'Apple Color Emoji','Apple SD Gothic Neo','Apple Symbols',
    'AppleGothic','AppleMyungjo','Arial Hebrew','Avenir','Avenir Next',
    'Avenir Next Condensed','Baskerville','Big Caslon','Bodoni 72',
    'Bodoni 72 Oldstyle','Bodoni 72 Smallcaps','Bradley Hand','Chalkboard',
    'Chalkboard SE','Chalkduster','Charter','Cochin','Copperplate',
    'Courier','Damascus','DecoType Naskh','Diwan Mishafi','Euphemia UCAS',
    'Farah','Futura','Geneva','Gill Sans','Helvetica','Helvetica Neue',
    'Herculanum','Hoefler Text','Kefa','Khmer Sangam MN','Kohinoor Bangla',
    'Marker Felt','Menlo','Monaco','Mshtakan','Mukta Mahee','Muna',
    'Myanmar Sangam MN','Nadeem','New Peninim MT','Noteworthy','Optima',
    'Osaka','Palatino','Papyrus','Phosphate','PingFang SC','PT Mono',
    'PT Sans','PT Serif','Rockwell','Savoye LET','Sinhala Sangam MN',
    'Skia','Snell Roundhand','Songti SC','STHeiti','STIXGeneral',
    'STIXSizeFiveSym','STIXSizeFourSym','STIXSizeOneSym','STIXSizeThreeSym',
    'STIXSizeTwoSym','STIXVariants','Symbol','Tamil Sangam MN',
    'Thonburi','Times','Trattatello','Zapf Dingbats','Zapfino',
    // Linux
    'Cantarell','DejaVu Sans','DejaVu Sans Mono','DejaVu Serif',
    'Droid Sans','Droid Sans Mono','Droid Serif','FreeMono','FreeSans',
    'FreeSerif','Liberation Mono','Liberation Sans','Liberation Serif',
    'Nimbus Mono PS','Nimbus Roman','Nimbus Sans','Noto Mono',
    'Noto Sans','Noto Serif','Ubuntu','Ubuntu Condensed','Ubuntu Mono',
    // Common web / Google Fonts (often system-installed)
    'Roboto','Open Sans','Lato','Oswald','Source Sans Pro','Montserrat',
    'Raleway','PT Sans','Merriweather','Nunito','Playfair Display',
    'Poppins','Fira Code','JetBrains Mono','Inter',
    // Misc
    'Wingdings 2','Wingdings 3','Webdings','MS Mincho','DFKai-SB',
    'BIZ UDGothic','BIZ UDMincho','Noto Color Emoji',
  ];

  const testString = 'mmmmmmmmmmlli';
  const testSize   = '72px';
  const baseline   = 'monospace';

  const c = document.createElement('canvas');
  c.width = 400; c.height = 120;
  const ctx = c.getContext('2d');

  function measureWidth(font) {
    ctx.font = testSize + ' ' + font + ', ' + baseline;
    return ctx.measureText(testString).width;
  }
  const baseW = measureWidth(baseline);

  const detected = [];
  fontList.forEach(f => {
    if (measureWidth(f) !== baseW) detected.push(f);
  });

  const body = document.getElementById('body-fonts');
  body.innerHTML = '';

  const info = document.createElement('div');
  info.className = 'row';
  info.innerHTML = `<span class="row-key">Fonts tested</span><span class="row-val">${fontList.length}</span>`;
  body.appendChild(info);

  const found = document.createElement('div');
  found.className = 'row';
  found.innerHTML = `<span class="row-key">Fonts detected</span><span class="row-val green">${detected.length}</span>`;
  body.appendChild(found);

  const grid = document.createElement('div');
  grid.id = 'font-grid';
  detected.forEach(f => {
    grid.innerHTML += tag(f, 'item');
  });
  body.appendChild(grid);

  document.getElementById('cnt-fonts').textContent = detected.length + ' / ' + fontList.length;
  FP.fonts = fnv32a(detected.join(','));
}

/* ═══════════════════════════════════════════════════════════════════════════
   §8  LOCALE & TIMEZONE
═══════════════════════════════════════════════════════════════════════════ */
function collectLocale() {
  setProgress(60, 'Reading locale and timezone...');
  const dtf = Intl.DateTimeFormat().resolvedOptions();
  const tz  = dtf.timeZone;
  const offset = -(new Date().getTimezoneOffset());
  const sign   = offset >= 0 ? '+' : '';
  const offStr = `UTC${sign}${Math.floor(offset/60)}:${String(Math.abs(offset%60)).padStart(2,'0')}`;

  const rows = [
    ['Timezone (IANA)',       tz, 'yellow'],
    ['UTC offset',            offStr, ''],
    ['Raw offset (minutes)',  String(offset), ''],
    ['DTF locale',            dtf.locale, 'cyan'],
    ['DTF calendar',          dtf.calendar, ''],
    ['DTF numberingSystem',   dtf.numberingSystem, ''],
    ['navigator.language',    navigator.language, ''],
    ['navigator.languages',   (navigator.languages||[]).join(', '), ''],
    ['Current local time',    new Date().toLocaleString(), ''],
    ['ISO timestamp',         new Date().toISOString(), 'dim'],
  ];

  // Intl number format
  try {
    const nf = new Intl.NumberFormat().resolvedOptions();
    rows.push(['Number locale',         nf.locale, '']);
    rows.push(['Number numberingSystem',nf.numberingSystem, '']);
  } catch(e) {}

  // Intl collator
  try {
    const co = new Intl.Collator().resolvedOptions();
    rows.push(['Collator locale',   co.locale, '']);
    rows.push(['Collator usage',    co.usage, '']);
    rows.push(['Collator caseFirst',co.caseFirst, '']);
  } catch(e) {}

  // Intl.supportedValuesOf (Chromium 99+)
  if (Intl.supportedValuesOf) {
    try {
      const cals = Intl.supportedValuesOf('calendar');
      rows.push(['Supported calendars', String(cals.length) + ' → ' + cals.slice(0,5).join(', ') + '…', 'dim']);
      const czs = Intl.supportedValuesOf('timeZone');
      rows.push(['Supported timezones', String(czs.length), 'dim']);
    } catch(e) {}
  }

  FP.timezone = tz;
  FP.locale   = navigator.language;
  renderRows('body-locale', rows, 'cnt-locale');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §9  NETWORK
═══════════════════════════════════════════════════════════════════════════ */
function collectNetwork() {
  setProgress(63, 'Probing network info...');
  const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
  const rows = [
    ['navigator.onLine',        yesno(navigator.onLine), ''],
  ];

  if (conn) {
    rows.push(['effectiveType',     conn.effectiveType || '—', 'cyan']);
    rows.push(['type',              conn.type          || '(not exposed)', '']);
    rows.push(['downlink (Mbps)',   conn.downlink != null ? conn.downlink + ' Mbps' : '—', 'green']);
    rows.push(['downlinkMax (Mbps)',conn.downlinkMax != null ? conn.downlinkMax + ' Mbps' : '—', '']);
    rows.push(['rtt (ms)',          conn.rtt != null ? conn.rtt + ' ms' : '—', 'yellow']);
    rows.push(['saveData',          yesno(conn.saveData), '']);
  } else {
    rows.push(['Network Information API', '(not available)', 'dim']);
  }

  rows.push(['PHP REMOTE_ADDR',   PHP_DATA.remote_addr || '—', 'yellow']);
  rows.push(['X-Forwarded-For',   PHP_DATA.forwarded_for || '(none)', '']);
  rows.push(['X-Real-IP',         PHP_DATA.real_ip || '(none)', '']);
  rows.push(['Server protocol',   PHP_DATA.server_protocol || '—', '']);

  renderRows('body-network', rows, 'cnt-network');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §10 BATTERY
═══════════════════════════════════════════════════════════════════════════ */
function collectBattery() {
  setProgress(66, 'Querying battery status...');
  const rows = [];
  if (!navigator.getBattery) {
    rows.push(['Battery API', 'NOT available', 'dim']);
    renderRows('body-battery', rows, 'cnt-battery');
    return Promise.resolve();
  }
  return navigator.getBattery().then(b => {
    rows.push(['charging',        yesno(b.charging), '']);
    rows.push(['level',           (b.level * 100).toFixed(1) + '%', b.level > 0.5 ? 'green' : b.level > 0.2 ? 'yellow' : 'red']);
    rows.push(['chargingTime',    b.chargingTime === Infinity ? '∞ (not charging)' : b.chargingTime + 's', '']);
    rows.push(['dischargingTime', b.dischargingTime === Infinity ? '∞ (charging or N/A)' : b.dischargingTime + 's', '']);
    FP.battery = `${b.charging?1:0}:${b.level}`;
    renderRows('body-battery', rows, 'cnt-battery');
    addStatusChip('🔋 ' + (b.level*100).toFixed(0)+'%', b.level > 0.5 ? 'ok' : 'warn');
  }).catch(e => {
    rows.push(['Battery API error', e.message, 'red']);
    renderRows('body-battery', rows, 'cnt-battery');
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   §11 STORAGE & MEMORY
═══════════════════════════════════════════════════════════════════════════ */
function collectStorage() {
  setProgress(69, 'Measuring storage and memory...');
  const rows = [];

  rows.push(['localStorage',        yesno(typeof localStorage !== 'undefined'), '']);
  rows.push(['sessionStorage',      yesno(typeof sessionStorage !== 'undefined'), '']);
  rows.push(['indexedDB',           yesno(typeof indexedDB !== 'undefined'), '']);
  rows.push(['caches (Cache API)',  yesno('caches' in window), '']);
  rows.push(['cookieStore',         yesno('cookieStore' in window), '']);

  // JS heap memory
  const mem = performance.memory;
  if (mem) {
    rows.push(['jsHeapSizeLimit',    (mem.jsHeapSizeLimit / 1048576).toFixed(1) + ' MB', 'cyan']);
    rows.push(['totalJSHeapSize',    (mem.totalJSHeapSize / 1048576).toFixed(1) + ' MB', '']);
    rows.push(['usedJSHeapSize',     (mem.usedJSHeapSize / 1048576).toFixed(1) + ' MB', 'green']);
  } else {
    rows.push(['JS heap memory',     '(not exposed — non-Chromium?)', 'dim']);
  }

  rows.push(['hardwareConcurrency', String(navigator.hardwareConcurrency || 0) + ' logical cores', 'green']);
  rows.push(['deviceMemory',        navigator.deviceMemory != null ? navigator.deviceMemory + ' GB' : '(not exposed)', '']);

  // WebAssembly
  rows.push(['WebAssembly',         yesno(typeof WebAssembly !== 'undefined'), '']);
  if (typeof WebAssembly !== 'undefined') {
    rows.push(['WASM streaming compile', yesno(typeof WebAssembly.compileStreaming === 'function'), '']);
    rows.push(['WASM SIMD (feature test)', (() => {
      try {
        // Magic bytes for a WASM module with SIMD
        return WebAssembly.validate(new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,123,3,2,1,0,10,10,1,8,0,65,0,253,15,253,98,11])) ?
          tag('SUPPORTED','yes') : tag('NO','no');
      } catch(e) { return tag('NO','no'); }
    })(), '']);
    rows.push(['SharedArrayBuffer', yesno(typeof SharedArrayBuffer !== 'undefined'), typeof SharedArrayBuffer !== 'undefined' ? '' : 'warn']);
  }

  renderRows('body-storage', rows, 'cnt-storage');

  // Storage estimate (async)
  if (navigator.storage && navigator.storage.estimate) {
    navigator.storage.estimate().then(est => {
      appendRow('body-storage', 'storage.quota',  est.quota ? (est.quota/1073741824).toFixed(2) + ' GB' : '—', 'cyan');
      appendRow('body-storage', 'storage.usage',  est.usage ? (est.usage/1048576).toFixed(2) + ' MB' : '—', '');
      if (est.usageDetails) {
        Object.entries(est.usageDetails).forEach(([k,v]) => {
          appendRow('body-storage', 'storage.'+k, (v/1024).toFixed(1) + ' KB', 'dim');
        });
      }
    }).catch(()=>{});
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   §12 MEDIA DEVICES
═══════════════════════════════════════════════════════════════════════════ */
function collectMedia() {
  setProgress(72, 'Enumerating media devices...');
  const rows = [];
  if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
    rows.push(['MediaDevices API', 'NOT available', 'red']);
    renderRows('body-media', rows, 'cnt-media');
    return Promise.resolve();
  }
  return navigator.mediaDevices.enumerateDevices().then(devices => {
    const audio_in  = devices.filter(d => d.kind === 'audioinput');
    const audio_out = devices.filter(d => d.kind === 'audiooutput');
    const video_in  = devices.filter(d => d.kind === 'videoinput');

    rows.push(['Total devices',         String(devices.length), 'cyan']);
    rows.push(['Audio inputs',          String(audio_in.length), '']);
    rows.push(['Audio outputs',         String(audio_out.length), '']);
    rows.push(['Video inputs (cameras)',String(video_in.length), 'green']);

    devices.forEach((d, i) => {
      const label = d.label || '(label hidden — no permission)';
      rows.push([`Device ${i+1} [${d.kind}]`, `${label} — deviceId:${d.deviceId.substring(0,16)}…`, 'dim']);
    });

    // MediaCapabilities probes
    if (navigator.mediaCapabilities) {
      rows.push(['MediaCapabilities API', 'Available', 'green']);
    }

    FP.mediaDevices = String(devices.length);
    renderRows('body-media', rows, 'cnt-media');
  }).catch(e => {
    rows.push(['enumerateDevices error', e.message, 'red']);
    renderRows('body-media', rows, 'cnt-media');
  });
}

/* ═══════════════════════════════════════════════════════════════════════════
   §13 SPEECH SYNTHESIS
═══════════════════════════════════════════════════════════════════════════ */
function collectSpeech() {
  setProgress(75, 'Enumerating speech voices...');
  const body = document.getElementById('body-speech');

  function renderVoices() {
    const synth = window.speechSynthesis;
    if (!synth) {
      body.innerHTML = '<div class="row"><span class="row-key">Speech Synthesis</span><span class="row-val red">NOT available</span></div>';
      document.getElementById('cnt-speech').textContent = '0';
      return;
    }
    const voices = synth.getVoices();
    body.innerHTML = '';
    const r0 = document.createElement('div'); r0.className='row';
    r0.innerHTML=`<span class="row-key">Total voices</span><span class="row-val cyan">${voices.length}</span>`;
    body.appendChild(r0);

    voices.forEach((v, i) => {
      const r = document.createElement('div'); r.className='row';
      r.innerHTML=`<span class="row-key">Voice ${i+1}</span><span class="row-val dim">${v.name} — ${v.lang}${v.localService?' [local]':' [remote]'}${v.default?' ★':''}</span>`;
      body.appendChild(r);
    });
    document.getElementById('cnt-speech').textContent = String(voices.length);
    FP.voices = String(voices.length);
  }

  if (window.speechSynthesis) {
    window.speechSynthesis.onvoiceschanged = renderVoices;
    renderVoices();
  } else {
    body.innerHTML = '<div class="row"><span class="row-key">Speech Synthesis</span><span class="row-val dim">NOT available</span></div>';
    document.getElementById('cnt-speech').textContent = '0';
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   §14 PERMISSIONS
═══════════════════════════════════════════════════════════════════════════ */
async function collectPermissions() {
  setProgress(78, 'Querying permissions API...');
  const rows = [];
  const perms = [
    'geolocation','notifications','push','midi','camera','microphone',
    'ambient-light-sensor','accelerometer','gyroscope','magnetometer',
    'clipboard-read','clipboard-write','payment-handler',
    'background-sync','persistent-storage','screen-wake-lock',
    'nfc','idle-detection','window-management',
  ];

  if (!navigator.permissions) {
    rows.push(['Permissions API', 'NOT available', 'dim']);
    renderRows('body-permissions', rows, 'cnt-permissions');
    return;
  }

  const results = await Promise.all(perms.map(async p => {
    try {
      const r = await navigator.permissions.query({name: p});
      return [p, r.state];
    } catch(e) {
      return [p, 'error: '+e.message.split(' ')[0]];
    }
  }));

  results.forEach(([p, state]) => {
    let cls = '';
    if (state === 'granted')  cls = 'green';
    if (state === 'denied')   cls = 'red';
    if (state === 'prompt')   cls = 'yellow';
    rows.push([p, state, cls]);
  });

  renderRows('body-permissions', rows, 'cnt-permissions');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §15 WEBRTC LOCAL IP
═══════════════════════════════════════════════════════════════════════════ */
function collectWebRTC() {
  setProgress(81, 'Probing WebRTC ICE candidates...');
  const body = document.getElementById('body-webrtc');
  const ips  = new Set();

  const r0 = document.createElement('div'); r0.className='row';
  r0.innerHTML='<span class="row-key">WebRTC status</span><span class="row-val dim">Collecting ICE candidates…</span>';
  body.appendChild(r0);

  if (!window.RTCPeerConnection) {
    body.innerHTML = '<div class="row"><span class="row-key">WebRTC</span><span class="row-val red">NOT available (RTCPeerConnection missing)</span></div>';
    document.getElementById('cnt-webrtc').textContent = '0';
    return;
  }

  try {
    const pc = new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
    pc.createDataChannel('fp');

    pc.onicecandidate = e => {
      if (!e || !e.candidate) {
        // Gathering complete
        pc.close();
        body.innerHTML = '';
        const stat = document.createElement('div'); stat.className='row';
        stat.innerHTML = `<span class="row-key">Unique IPs found</span><span class="row-val ${ips.size > 0 ? 'yellow' : 'dim'}">${ips.size}</span>`;
        body.appendChild(stat);
        ips.forEach(ip => {
          const r = document.createElement('div'); r.className='row';
          const cls = ip.startsWith('192.168') || ip.startsWith('10.') || ip.startsWith('172.') ? 'yellow' : 'cyan';
          r.innerHTML = `<span class="row-key">Local IP</span><span class="row-val ${cls}">${ip}</span>`;
          body.appendChild(r);
        });
        document.getElementById('cnt-webrtc').textContent = String(ips.size);
        FP.rtcIPs = Array.from(ips).join(',');
        return;
      }
      const parts = e.candidate.candidate.split(' ');
      if (parts[7] === 'host') {
        const ip = parts[4];
        if (ip && !ip.includes('.local')) ips.add(ip);
      }
    };

    pc.createOffer().then(o => pc.setLocalDescription(o)).catch(()=>{});
    setTimeout(() => { try { pc.close(); } catch(e) {} }, 5000);
  } catch(e) {
    body.innerHTML = `<div class="row"><span class="row-key">WebRTC error</span><span class="row-val red">${e.message}</span></div>`;
    document.getElementById('cnt-webrtc').textContent = '0';
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
   §16 CSS MEDIA FEATURES
═══════════════════════════════════════════════════════════════════════════ */
function collectCSS() {
  setProgress(84, 'Evaluating CSS media features...');
  function mq(q) { return window.matchMedia(q).matches; }

  const rows = [
    ['prefers-color-scheme: dark',      yesno(mq('(prefers-color-scheme:dark)')), ''],
    ['prefers-color-scheme: light',     yesno(mq('(prefers-color-scheme:light)')), ''],
    ['prefers-reduced-motion: reduce',  yesno(mq('(prefers-reduced-motion:reduce)')), ''],
    ['prefers-contrast: more',          yesno(mq('(prefers-contrast:more)')), ''],
    ['prefers-contrast: less',          yesno(mq('(prefers-contrast:less)')), ''],
    ['forced-colors: active',           yesno(mq('(forced-colors:active)')), ''],
    ['inverted-colors: inverted',       yesno(mq('(inverted-colors:inverted)')), ''],
    ['pointer: coarse',                 yesno(mq('(pointer:coarse)')), ''],
    ['pointer: fine',                   yesno(mq('(pointer:fine)')), ''],
    ['pointer: none',                   yesno(mq('(pointer:none)')), ''],
    ['hover: hover',                    yesno(mq('(hover:hover)')), ''],
    ['hover: none',                     yesno(mq('(hover:none)')), ''],
    ['any-pointer: coarse',             yesno(mq('(any-pointer:coarse)')), ''],
    ['any-pointer: fine',               yesno(mq('(any-pointer:fine)')), ''],
    ['any-hover: hover',                yesno(mq('(any-hover:hover)')), ''],
    ['color-gamut: srgb',               yesno(mq('(color-gamut:srgb)')), ''],
    ['color-gamut: p3',                 yesno(mq('(color-gamut:p3)')), 'green'],
    ['color-gamut: rec2020',            yesno(mq('(color-gamut:rec2020)')), ''],
    ['dynamic-range: high (HDR)',       yesno(mq('(dynamic-range:high)')), 'green'],
    ['update: fast',                    yesno(mq('(update:fast)')), ''],
    ['overflow-block: scroll',          yesno(mq('(overflow-block:scroll)')), ''],
    ['orientation: landscape',          yesno(mq('(orientation:landscape)')), ''],
    ['orientation: portrait',           yesno(mq('(orientation:portrait)')), ''],
    ['prefers-reduced-data: reduce',    yesno(mq('(prefers-reduced-data:reduce)')), ''],
    ['display-mode: standalone',        yesno(mq('(display-mode:standalone)')), ''],
    ['display-mode: fullscreen',        yesno(mq('(display-mode:fullscreen)')), ''],
    ['min-resolution: 2dppx',           yesno(mq('(min-resolution:2dppx)')), 'yellow'],
    ['min-resolution: 3dppx',           yesno(mq('(min-resolution:3dppx)')), ''],
    ['CSS color p3 support',            yesno(CSS.supports && CSS.supports('color','color(display-p3 1 0 0)')), ''],
    ['CSS oklch support',               yesno(CSS.supports && CSS.supports('color','oklch(60% 0.2 240)')), ''],
    ['CSS container queries',           yesno(CSS.supports && CSS.supports('container-type','inline-size')), ''],
    ['CSS @layer support',              yesno(CSS.supports && CSS.supports('@layer', '')), ''],
    ['CSS subgrid',                     yesno(CSS.supports && CSS.supports('grid-template-rows','subgrid')), ''],
    ['CSS :has() selector',             yesno(CSS.supports && CSS.supports('selector(:has(*))')), ''],
    ['CSS nesting',                     yesno(CSS.supports && CSS.supports('selector(a & b)')), ''],
  ];

  FP.prefersColorScheme = mq('(prefers-color-scheme:dark)') ? 'dark' : 'light';
  renderRows('body-css', rows, 'cnt-css');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §17 FEATURE DETECTION
═══════════════════════════════════════════════════════════════════════════ */
function collectFeatures() {
  setProgress(87, 'Running feature detection matrix...');
  const w = window;
  const n = navigator;

  const feats = [
    // JS runtime
    ['BigInt',                    typeof BigInt !== 'undefined'],
    ['Proxy',                     typeof Proxy !== 'undefined'],
    ['Promise',                   typeof Promise !== 'undefined'],
    ['Symbol',                    typeof Symbol !== 'undefined'],
    ['WeakRef',                   typeof WeakRef !== 'undefined'],
    ['FinalizationRegistry',      typeof FinalizationRegistry !== 'undefined'],
    ['globalThis',                typeof globalThis !== 'undefined'],
    ['structuredClone',           typeof structuredClone !== 'undefined'],
    ['Error.cause',               typeof Error({cause:0}).cause !== 'undefined'],
    ['Array.at()',                 typeof [].at === 'function'],
    ['Object.hasOwn()',           typeof Object.hasOwn === 'function'],
    ['String.replaceAll()',       typeof ''.replaceAll === 'function'],
    ['queueMicrotask',            typeof queueMicrotask === 'function'],
    ['AbortController',           typeof AbortController !== 'undefined'],
    // Browser APIs
    ['Fetch API',                 typeof fetch !== 'undefined'],
    ['Service Worker',            'serviceWorker' in n],
    ['Web Workers',               typeof Worker !== 'undefined'],
    ['WebSocket',                 typeof WebSocket !== 'undefined'],
    ['WebAssembly',               typeof WebAssembly !== 'undefined'],
    ['SharedArrayBuffer',         typeof SharedArrayBuffer !== 'undefined'],
    ['Atomics',                   typeof Atomics !== 'undefined'],
    ['Broadcast Channel',         typeof BroadcastChannel !== 'undefined'],
    ['MessageChannel',            typeof MessageChannel !== 'undefined'],
    ['ReadableStream',            typeof ReadableStream !== 'undefined'],
    ['WritableStream',            typeof WritableStream !== 'undefined'],
    ['TransformStream',           typeof TransformStream !== 'undefined'],
    ['CompressionStream',         typeof CompressionStream !== 'undefined'],
    // Observers
    ['IntersectionObserver',      typeof IntersectionObserver !== 'undefined'],
    ['ResizeObserver',            typeof ResizeObserver !== 'undefined'],
    ['MutationObserver',          typeof MutationObserver !== 'undefined'],
    ['PerformanceObserver',       typeof PerformanceObserver !== 'undefined'],
    ['ReportingObserver',         typeof window.ReportingObserver !== 'undefined'],
    // Crypto
    ['Web Crypto API',            typeof crypto !== 'undefined' && !!crypto.subtle],
    ['crypto.randomUUID()',       typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'],
    // Storage
    ['localStorage',              typeof localStorage !== 'undefined'],
    ['sessionStorage',            typeof sessionStorage !== 'undefined'],
    ['indexedDB',                 typeof indexedDB !== 'undefined'],
    ['Cache API',                 typeof caches !== 'undefined'],
    ['File System Access API',    typeof window.showOpenFilePicker !== 'undefined'],
    // Media
    ['MediaDevices',              !!(n.mediaDevices)],
    ['Screen Capture API',        !!(n.mediaDevices && n.mediaDevices.getDisplayMedia)],
    ['Picture-in-Picture',        typeof document.pictureInPictureEnabled !== 'undefined'],
    ['Web Audio API',             typeof AudioContext !== 'undefined' || typeof window.webkitAudioContext !== 'undefined'],
    ['Speech Recognition',        typeof window.SpeechRecognition !== 'undefined' || typeof window.webkitSpeechRecognition !== 'undefined'],
    ['Speech Synthesis',          typeof speechSynthesis !== 'undefined'],
    // Input / Sensing
    ['Pointer Events',            typeof PointerEvent !== 'undefined'],
    ['Touch Events',              typeof TouchEvent !== 'undefined'],
    ['Gamepad API',               typeof navigator.getGamepads === 'function'],
    ['DeviceOrientation',         typeof DeviceOrientationEvent !== 'undefined'],
    ['DeviceMotion',              typeof DeviceMotionEvent !== 'undefined'],
    ['Ambient Light Sensor',      typeof window.AmbientLightSensor !== 'undefined'],
    ['Accelerometer',             typeof window.Accelerometer !== 'undefined'],
    ['Gyroscope',                 typeof window.Gyroscope !== 'undefined'],
    ['Magnetometer',              typeof window.Magnetometer !== 'undefined'],
    // Network / Connectivity
    ['WebRTC',                    typeof RTCPeerConnection !== 'undefined'],
    ['Navigator.connection',      !!navigator.connection],
    ['Background Sync',           typeof window.SyncManager !== 'undefined'],
    ['Push API',                  typeof window.PushManager !== 'undefined'],
    ['Notifications API',         typeof Notification !== 'undefined'],
    ['Web Share API',             typeof navigator.share === 'function'],
    ['Clipboard API',             !!navigator.clipboard],
    // Display / UI
    ['WebGPU',                    !!navigator.gpu],
    ['Screen Wake Lock',          typeof navigator.wakeLock !== 'undefined'],
    ['Window Controls Overlay',   !!navigator.windowControlsOverlay],
    ['View Transition API',       typeof document.startViewTransition === 'function'],
    ['Popover API',               typeof document.createElement('div').showPopover === 'function'],
    ['CSS Houdini Paint',         typeof CSS.paintWorklet !== 'undefined'],
    // Payments / ID
    ['Payment Request API',       typeof PaymentRequest !== 'undefined'],
    ['Credential Mgmt API',       !!navigator.credentials],
    ['FedCM API',                 typeof window.IdentityCredential !== 'undefined'],
    // Misc
    ['Web NFC',                   typeof window.NDEFReader !== 'undefined'],
    ['Web USB',                   !!navigator.usb],
    ['Web Serial',                !!navigator.serial],
    ['Web Bluetooth',             !!navigator.bluetooth],
    ['WebHID',                    !!navigator.hid],
    ['WebMIDI',                   typeof navigator.requestMIDIAccess === 'function'],
    ['Eye Dropper',               typeof window.EyeDropper !== 'undefined'],
    ['Idle Detection',            typeof window.IdleDetector !== 'undefined'],
    ['Local Font Access',         typeof navigator.fonts !== 'undefined'],
  ];

  const body = document.getElementById('body-features');
  body.innerHTML = '';
  feats.forEach(([name, supported]) => {
    const r = document.createElement('div'); r.className='row';
    r.innerHTML = `<span class="row-key">${name}</span><span class="row-val">${yesno(!!supported)}</span>`;
    body.appendChild(r);
  });
  document.getElementById('cnt-features').textContent = feats.length + ' APIs';
  FP.featHash = fnv32a(feats.map(([,v])=>v?1:0).join(''));
}

/* ═══════════════════════════════════════════════════════════════════════════
   §18 MATH / FPU FINGERPRINT
═══════════════════════════════════════════════════════════════════════════ */
function collectMath() {
  setProgress(90, 'Computing FPU fingerprint...');
  const tests = [
    ['Math.PI',                   Math.PI],
    ['Math.E',                    Math.E],
    ['Math.sqrt(2)',               Math.sqrt(2)],
    ['Math.sin(1)',                Math.sin(1)],
    ['Math.cos(1)',                Math.cos(1)],
    ['Math.tan(1)',                Math.tan(1)],
    ['Math.asin(0.5)',             Math.asin(0.5)],
    ['Math.acos(0.5)',             Math.acos(0.5)],
    ['Math.atan(1)',               Math.atan(1)],
    ['Math.atan2(1,2)',            Math.atan2(1,2)],
    ['Math.exp(1)',                Math.exp(1)],
    ['Math.log(2)',                Math.log(2)],
    ['Math.log2(1024)',            Math.log2(1024)],
    ['Math.log10(1000)',           Math.log10(1000)],
    ['Math.cbrt(2)',               Math.cbrt(2)],
    ['Math.hypot(3,4)',            Math.hypot(3,4)],
    ['Math.sinh(1)',               Math.sinh(1)],
    ['Math.cosh(1)',               Math.cosh(1)],
    ['Math.tanh(1)',               Math.tanh(1)],
    ['Math.expm1(1)',              Math.expm1(1)],
    ['Math.log1p(1)',              Math.log1p(1)],
    ['1e+308 overflow',           1e308 * 2],
    ['Number.EPSILON',             Number.EPSILON],
    ['Number.MAX_SAFE_INTEGER',    Number.MAX_SAFE_INTEGER],
    ['Number.MIN_SAFE_INTEGER',    Number.MIN_SAFE_INTEGER],
    ['0.1 + 0.2',                  0.1 + 0.2],
    ['1/3',                        1/3],
    ['Math.fround(1.1)',           Math.fround(1.1)],
    ['Math.clz32(1)',              Math.clz32(1)],
    ['Math.imul(3,4)',             Math.imul(3,4)],
    ['Math.trunc(-4.5)',           Math.trunc(-4.5)],
    ['Math.sign(-5)',              Math.sign(-5)],
  ];

  const rows = tests.map(([k,v]) => [k, String(v), '']);
  const fpHash = fnv32a(tests.map(([,v])=>String(v)).join(','));
  rows.unshift(['FPU fingerprint hash', fpHash, 'cyan']);
  FP.mathHash = fpHash;
  renderRows('body-math', rows, 'cnt-math');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §19 PERFORMANCE
═══════════════════════════════════════════════════════════════════════════ */
function collectPerf() {
  setProgress(93, 'Reading performance metrics...');
  const rows = [];
  const p = performance;

  rows.push(['timeOrigin',     p.timeOrigin.toFixed(3) + ' ms (Unix epoch offset)', 'dim']);
  rows.push(['now()',          p.now().toFixed(3) + ' ms (since page load)', 'green']);

  // Navigation timing
  const nav = p.getEntriesByType('navigation')[0];
  if (nav) {
    rows.push(['navType',            nav.type, '']);
    rows.push(['redirectCount',      String(nav.redirectCount), '']);
    rows.push(['DNS lookup',         (nav.domainLookupEnd - nav.domainLookupStart).toFixed(2) + ' ms', '']);
    rows.push(['TCP connect',        (nav.connectEnd - nav.connectStart).toFixed(2) + ' ms', '']);
    rows.push(['TLS handshake',      (nav.requestStart - nav.secureConnectionStart > 0 ? (nav.requestStart - nav.secureConnectionStart).toFixed(2) : '0.00') + ' ms', '']);
    rows.push(['TTFB',               (nav.responseStart - nav.requestStart).toFixed(2) + ' ms', 'yellow']);
    rows.push(['DOM interactive',    (nav.domInteractive - nav.startTime).toFixed(2) + ' ms', '']);
    rows.push(['DOM complete',       (nav.domComplete - nav.startTime).toFixed(2) + ' ms', '']);
    rows.push(['Load event',         (nav.loadEventEnd - nav.startTime).toFixed(2) + ' ms', 'cyan']);
    rows.push(['transferSize',       String(nav.transferSize) + ' bytes', '']);
    rows.push(['decodedBodySize',    String(nav.decodedBodySize) + ' bytes', '']);
    rows.push(['protocol',           nav.nextHopProtocol || '(not exposed)', 'green']);
    rows.push(['renderBlockingStatus', nav.renderBlockingStatus || 'n/a', '']);
  }

  // Paint timing
  const paints = p.getEntriesByType('paint');
  paints.forEach(e => {
    rows.push([e.name, e.startTime.toFixed(2) + ' ms', 'yellow']);
  });

  // LCP
  try {
    const lo = new PerformanceObserver(list => {
      const entries = list.getEntries();
      const last = entries[entries.length - 1];
      appendRow('body-perf', 'LCP', last.startTime.toFixed(2) + ' ms', 'green');
    });
    lo.observe({type:'largest-contentful-paint', buffered: true});
  } catch(e) {}

  // FID / CLS / INP placeholders via PerformanceObserver
  rows.push(['PerformanceObserver',  yesno(typeof PerformanceObserver !== 'undefined'), '']);

  renderRows('body-perf', rows, 'cnt-perf');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §20 INPUT CAPABILITIES
═══════════════════════════════════════════════════════════════════════════ */
function collectInput() {
  setProgress(96, 'Probing input capabilities...');
  const rows = [
    ['maxTouchPoints',       String(navigator.maxTouchPoints), navigator.maxTouchPoints > 0 ? 'yellow' : ''],
    ['Touch Events API',     yesno('ontouchstart' in window || navigator.maxTouchPoints > 0), ''],
    ['Pointer Events API',   yesno(typeof PointerEvent !== 'undefined'), ''],
    ['Mouse Events',         yesno(typeof MouseEvent !== 'undefined'), ''],
    ['Keyboard Events',      yesno(typeof KeyboardEvent !== 'undefined'), ''],
    ['navigator.keyboard',   yesno('keyboard' in navigator), ''],
    ['DeviceOrientation',    yesno(typeof DeviceOrientationEvent !== 'undefined'), ''],
    ['DeviceMotion',         yesno(typeof DeviceMotionEvent !== 'undefined'), ''],
    ['Gamepad API',          yesno(typeof navigator.getGamepads === 'function'), ''],
    ['Vibration API',        yesno(typeof navigator.vibrate === 'function'), ''],
    ['Pen/stylus capable',   yesno(window.matchMedia('(any-pointer:fine)').matches && navigator.maxTouchPoints > 0), ''],
  ];

  // Gamepad probe
  if (typeof navigator.getGamepads === 'function') {
    const gpads = Array.from(navigator.getGamepads()).filter(Boolean);
    rows.push(['Connected gamepads', String(gpads.length), gpads.length > 0 ? 'green' : '']);
    gpads.forEach((g, i) => {
      rows.push([`Gamepad ${i}`, `${g.id} — ${g.buttons.length} buttons, ${g.axes.length} axes`, 'dim']);
    });
  }

  renderRows('body-input', rows, 'cnt-input');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §21 PHP RAW SERVER
═══════════════════════════════════════════════════════════════════════════ */
function renderPHPRaw() {
  const body = document.getElementById('body-php');
  const pre = document.createElement('pre');
  pre.className = 'raw-block';
  pre.textContent = JSON.stringify(PHP_DATA.server, null, 2);
  body.appendChild(pre);
  document.getElementById('cnt-php').textContent = Object.keys(PHP_DATA.server||{}).length + ' vars';
}


/* ═══════════════════════════════════════════════════════════════════════════
   §22  WEBKIT / SAFARI / APPLE PLATFORM
   Covers Safari (macOS), MobileSafari (iOS/iPadOS), and WebKit-based apps.
   Tests fall into three tiers:
     A) Definitive — only present in WebKit/JavaScriptCore
     B) Strong indicator — heavily WebKit-weighted but occasionally elsewhere
     C) Derived — parsed from UA / capability inference
═══════════════════════════════════════════════════════════════════════════ */
async function collectWebKit() {
  setProgress(91, 'Running WebKit/Safari/Apple probes...');
  const rows = [];
  const ua   = navigator.userAgent;
  const w    = window;
  const n    = navigator;
  const doc  = document;

  /* ── Tier A: Definitive WebKit / JavaScriptCore identifiers ─────────── */

  // window.safari only exists in desktop Safari (not Chrome/Firefox)
  const hasSafariObj = typeof w.safari !== 'undefined';
  rows.push(['window.safari object',        yesno(hasSafariObj),
    hasSafariObj ? 'green' : 'dim']);

  // Apple Pay — available on Safari+Apple device or macOS Safari
  const hasApplePay = typeof w.ApplePaySession !== 'undefined';
  rows.push(['ApplePaySession (Apple Pay)',  yesno(hasApplePay),
    hasApplePay ? 'green' : 'dim']);
  if (hasApplePay) {
    try {
      rows.push(['ApplePay canMakePayments',
        yesno(w.ApplePaySession.canMakePayments()),
        w.ApplePaySession.canMakePayments() ? 'green' : 'yellow']);
      // Version probing — Safari 10=1, 11=3, 12=4, 13=5, 14=6 etc.
      let apVer = 0;
      [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17].forEach(v => {
        if (w.ApplePaySession.supportsVersion && w.ApplePaySession.supportsVersion(v)) apVer = v;
      });
      rows.push(['ApplePaySession.supportsVersion max', apVer > 0 ? String(apVer) : 'n/a', 'yellow']);
    } catch(e) {
      rows.push(['ApplePay probe error', e.message, 'red']);
    }
  }

  // GestureEvent — iOS/Safari exclusive touch gesture event
  rows.push(['GestureEvent (iOS exclusive)', yesno(typeof w.GestureEvent !== 'undefined'),
    typeof w.GestureEvent !== 'undefined' ? 'green' : 'dim']);

  // DeviceOrientationEvent.requestPermission — iOS 13+ gate
  const hasOrientPerm = typeof DeviceOrientationEvent !== 'undefined' &&
                        typeof DeviceOrientationEvent.requestPermission === 'function';
  rows.push(['DeviceOrientationEvent.requestPermission (iOS 13+)', yesno(hasOrientPerm),
    hasOrientPerm ? 'yellow' : 'dim']);

  const hasMotionPerm = typeof DeviceMotionEvent !== 'undefined' &&
                        typeof DeviceMotionEvent.requestPermission === 'function';
  rows.push(['DeviceMotionEvent.requestPermission (iOS 13+)', yesno(hasMotionPerm),
    hasMotionPerm ? 'yellow' : 'dim']);

  // WebKitCSSMatrix — present in Safari, also Chrome (blink kept it)
  rows.push(['WebKitCSSMatrix', yesno(typeof w.WebKitCSSMatrix !== 'undefined'), '']);

  // webkitURL — Safari kept this long after others dropped it
  rows.push(['window.webkitURL',            yesno(typeof w.webkitURL !== 'undefined'), '']);

  // WebKit-prefixed fullscreen on video elements
  const vid = doc.createElement('video');
  const hasWKFS = typeof vid.webkitEnterFullscreen === 'function';
  rows.push(['HTMLVideoElement.webkitEnterFullscreen', yesno(hasWKFS),
    hasWKFS ? 'yellow' : 'dim']);
  const hasWKSupportsFS = typeof vid.webkitSupportsFullscreen !== 'undefined';
  rows.push(['HTMLVideoElement.webkitSupportsFullscreen', yesno(hasWKSupportsFS), '']);

  // webkitSpeechRecognition — originally WebKit, now also Chrome
  rows.push(['webkitSpeechRecognition',      yesno(typeof w.webkitSpeechRecognition !== 'undefined'), '']);

  // WebKitMutationObserver — legacy alias
  rows.push(['WebKitMutationObserver',       yesno(typeof w.WebKitMutationObserver !== 'undefined'), '']);

  // AudioContext prefixed
  rows.push(['webkitAudioContext',           yesno(typeof w.webkitAudioContext !== 'undefined'), '']);

  // IDBOpenDBRequest with webkit prefix (very old Safari)
  rows.push(['webkitIndexedDB',              yesno(typeof w.webkitIndexedDB !== 'undefined'), '']);

  // webkitRTCPeerConnection
  rows.push(['webkitRTCPeerConnection',      yesno(typeof w.webkitRTCPeerConnection !== 'undefined'), '']);

  // requestAnimationFrame webkit prefix
  rows.push(['webkitRequestAnimationFrame',  yesno(typeof w.webkitRequestAnimationFrame !== 'undefined'), '']);

  // MutationObserver webkit prefix
  rows.push(['WebKitMutationObserver',       yesno(typeof w.WebKitMutationObserver !== 'undefined'), '']);

  /* ── Tier B: navigator / DOM properties strong in WebKit ────────────── */

  // navigator.standalone — ONLY set by iOS Safari (home-screen PWA)
  const isStandalone = n.standalone;
  rows.push(['navigator.standalone (iOS PWA)',
    isStandalone === undefined ? tag('undefined — not iOS Safari','warn') :
    yesno(isStandalone), isStandalone ? 'green' : '']);

  // window.orientation — deprecated but iOS Safari still exposes it
  rows.push(['window.orientation (deprecated iOS)',
    typeof w.orientation !== 'undefined' ? String(w.orientation) + '°' : tag('undefined','dim'),
    typeof w.orientation !== 'undefined' ? 'yellow' : '']);

  /* ── Tier B: CSS -webkit- feature support ────────────────────────────── */
  function cssSup(prop, val) {
    return CSS && CSS.supports ? CSS.supports(prop, val) : false;
  }

  rows.push(['CSS -webkit-backdrop-filter', yesno(cssSup('-webkit-backdrop-filter', 'blur(1px)')), '']);
  rows.push(['CSS -webkit-appearance: none', yesno(cssSup('-webkit-appearance', 'none')), '']);
  rows.push(['CSS -webkit-text-fill-color',  yesno(cssSup('-webkit-text-fill-color', 'red')), '']);
  rows.push(['CSS -webkit-line-clamp',        yesno(cssSup('-webkit-line-clamp', '2')), '']);
  rows.push(['CSS -webkit-overflow-scrolling',yesno(cssSup('-webkit-overflow-scrolling','touch')), '']);
  rows.push(['CSS -webkit-touch-callout',     yesno(cssSup('-webkit-touch-callout', 'none')), '']);
  rows.push(['CSS color display-p3',          yesno(cssSup('color', 'color(display-p3 1 0 0)')), 'green']);
  rows.push(['CSS backdrop-filter (unprefixed)',yesno(cssSup('backdrop-filter','blur(1px)')), '']);

  /* ── Media / codec probes (Safari-distinctive formats) ─────────────── */
  const au = doc.createElement('audio');
  const vi = doc.createElement('video');
  const canPlay = (el, t) => { try { return el.canPlayType(t) || 'no'; } catch(e) { return 'error'; } };

  rows.push(['audio/x-m4a (AAC-LC in M4A)',  canPlay(au,'audio/x-m4a'), '']);
  rows.push(['audio/aac',                     canPlay(au,'audio/aac'), '']);
  rows.push(['audio/mp4; codecs=mp4a.40.2',  canPlay(au,'audio/mp4; codecs=mp4a.40.2'), '']);
  rows.push(['video/mp4; codecs=hvc1',        canPlay(vi,'video/mp4; codecs=hvc1'), 'yellow']);  // HEVC/H.265
  rows.push(['video/mp4; codecs=dvh1.20.L153',canPlay(vi,'video/mp4; codecs=dvh1.20.L153'), '']); // Dolby Vision
  rows.push(['HLS: application/vnd.apple.mpegurl', canPlay(vi,'application/vnd.apple.mpegurl'), 'green']); // only Safari native
  rows.push(['HLS: application/x-mpegURL',    canPlay(vi,'application/x-mpegURL'), '']);
  rows.push(['video/mp4; codecs=avc1',        canPlay(vi,'video/mp4; codecs=avc1'), '']);
  rows.push(['video/mp4; codecs=hev1',        canPlay(vi,'video/mp4; codecs=hev1'), '']);

  /* ── ITP / Storage Partitioning fingerprint ─────────────────────────── */
  // Safari's ITP partitions storage — we can detect reduced cookie lifetime
  rows.push(['document.hasStorageAccess API', yesno(typeof doc.hasStorageAccess === 'function'),
    typeof doc.hasStorageAccess === 'function' ? 'yellow' : '']);
  rows.push(['document.requestStorageAccess', yesno(typeof doc.requestStorageAccess === 'function'), '']);

  /* ── Privacy / Fingerprinting-resistance canvas noise test ──────────── */
  // Safari 17+ (and Firefox RFP) add noise to canvas. Test pixel fidelity.
  const noiseCanvas = doc.createElement('canvas');
  noiseCanvas.width = 20; noiseCanvas.height = 20;
  const nCtx = noiseCanvas.getContext('2d');
  nCtx.fillStyle = '#FF0000';
  nCtx.fillRect(0, 0, 1, 1);
  const px = nCtx.getImageData(0, 0, 1, 1).data;
  const canvasNoise = (px[0] !== 255 || px[1] !== 0 || px[2] !== 0);
  rows.push(['Canvas pixel noise detected', yesno(canvasNoise),
    canvasNoise ? 'yellow' : '']);

  /* ── Derived: UA string parsing ──────────────────────────────────────── */
  const isWebKit    = /WebKit/.test(ua) && !/Chromium/.test(ua);
  const isSafari    = /Safari/.test(ua) && !/Chrome/.test(ua);
  const isMobileSaf = /iPhone|iPad|iPod/.test(ua) && isSafari;
  const iosVerMatch = ua.match(/OS (\d+)[_\.](\d+)/);
  const safVerMatch = ua.match(/Version\/([\d.]+).*Safari/);
  const wkVerMatch  = ua.match(/AppleWebKit\/([\d.]+)/);

  rows.push(['UA: WebKit (not Chromium)',     yesno(isWebKit), isWebKit ? 'green' : 'dim']);
  rows.push(['UA: Safari (not Chrome-based)', yesno(isSafari), isSafari ? 'green' : 'dim']);
  rows.push(['UA: Mobile Safari (iOS)',       yesno(isMobileSaf), isMobileSaf ? 'green' : 'dim']);
  rows.push(['UA: iOS version',              iosVerMatch ? iosVerMatch[1]+'.'+iosVerMatch[2] : '(not iOS)', iosVerMatch ? 'yellow' : 'dim']);
  rows.push(['UA: Safari version',           safVerMatch ? safVerMatch[1] : '(not in UA)', '']);
  rows.push(['UA: AppleWebKit build',        wkVerMatch ? wkVerMatch[1] : '(not found)', 'cyan']);

  // Screen size → iOS device model hints
  const sw = screen.width, sh = screen.height, dpr = window.devicePixelRatio;
  let deviceHint = 'Unknown / not iOS';
  const logical = [Math.min(sw,sh), Math.max(sw,sh)];
  const iOS_sizes = [
    [[320,568], 'iPhone SE (1st gen) / iPhone 5/5s'],
    [[375,667], 'iPhone 6/7/8 / SE 2nd/3rd gen'],
    [[414,736], 'iPhone 6+/7+/8+'],
    [[375,812], 'iPhone X/XS/11 Pro / 12 mini / 13 mini'],
    [[414,896], 'iPhone XR/XS Max/11/11 Pro Max'],
    [[390,844], 'iPhone 12/13/14 Pro / 12/13'],
    [[428,926], 'iPhone 12/13/14 Pro Max'],
    [[393,852], 'iPhone 15/16 / 14 Pro'],
    [[430,932], 'iPhone 15/16 Plus / 14 Pro Max'],
    [[402,874], 'iPhone 16 Pro'],
    [[440,956], 'iPhone 16 Pro Max'],
    [[768,1024],'iPad (non-retina) / iPad mini 1-3'],
    [[810,1080],'iPad 7th/8th/9th gen'],
    [[820,1180],'iPad Air 4/5'],
    [[834,1194],'iPad Pro 11"'],
    [[1024,1366],'iPad Pro 12.9"'],
    [[744,1133],'iPad mini 6'],
  ];
  iOS_sizes.forEach(([[w2,h2], label]) => {
    if (logical[0] === w2 && logical[1] === h2) deviceHint = label;
  });
  rows.push(['iOS/iPadOS device hint', deviceHint, deviceHint !== 'Unknown / not iOS' ? 'yellow' : 'dim']);

  // Confidence score
  const signals = [hasSafariObj, hasApplePay, typeof w.GestureEvent !== 'undefined',
    hasOrientPerm, hasMotionPerm, isStandalone !== undefined, isSafari, isMobileSaf].filter(Boolean);
  const confidence = Math.round((signals.length / 8) * 100);
  rows.push(['WebKit/Safari confidence score', confidence + '%',
    confidence > 60 ? 'green' : confidence > 30 ? 'yellow' : 'dim']);

  FP.webkit = String(confidence) + '|' + (wkVerMatch ? wkVerMatch[1] : '') + '|' + (safVerMatch ? safVerMatch[1] : '');
  renderRows('body-webkit', rows, 'cnt-webkit');

  if (confidence > 40) addStatusChip('🍎 WebKit: ' + confidence + '%', 'ok');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §23  MICROSOFT EDGE / CHROMIUM-SPECIFIC
   Layers: Legacy EdgeHTML (dead), Chromium Edge (Edg/), IE compat mode.
   Also covers Chrome-exclusive Blink APIs that Edge inherits.
═══════════════════════════════════════════════════════════════════════════ */
async function collectEdge() {
  setProgress(93, 'Running Edge/Chromium-specific probes...');
  const rows = [];
  const w   = window;
  const n   = navigator;
  const ua  = n.userAgent;
  const doc = document;

  /* ── UA string dissection (first, sets context for everything else) ──── */
  const isChromium    = /Chrome\//.test(ua) && /Chromium\//.test(ua) === false;  // note: Chromium also sets Chrome/
  const isEdge        = /Edg\//.test(ua);                // Chromium Edge (2020+)
  const isEdgeHTML    = /Edge\//.test(ua);               // EdgeHTML (2015–2019, EOL)
  const isIE          = /Trident\//.test(ua);            // IE 11 (very unlikely in 2026 but worth detecting)
  const isChrome      = /Chrome\//.test(ua) && !isEdge && !isEdgeHTML;
  const edgeVerMatch  = ua.match(/Edg\/([\d.]+)/);
  const chromeVerMatch= ua.match(/Chrome\/([\d.]+)/);
  const tridentMatch  = ua.match(/Trident\/([\d.]+)/);

  rows.push(['UA: Chromium Edge (Edg/)',     yesno(isEdge),     isEdge    ? 'green' : 'dim']);
  rows.push(['UA: EdgeHTML (legacy)',        yesno(isEdgeHTML), isEdgeHTML? 'yellow': 'dim']);
  rows.push(['UA: Internet Explorer',        yesno(isIE),       isIE      ? 'red'   : 'dim']);
  rows.push(['UA: Chrome (not Edge)',        yesno(isChrome),   isChrome  ? 'cyan'  : 'dim']);
  rows.push(['Edge version',  edgeVerMatch   ? edgeVerMatch[1]  : '(not in UA)', edgeVerMatch ? 'yellow' : '']);
  rows.push(['Chrome version',chromeVerMatch ? chromeVerMatch[1]: '(not in UA)', '']);
  rows.push(['Trident version (IE)',tridentMatch ? tridentMatch[1] : '(none)', tridentMatch ? 'red' : 'dim']);

  /* ── UA-CH brand list (Chromium/Edge only) ────────────────────────────── */
  if (n.userAgentData) {
    const brands = (n.userAgentData.brands || []).map(b => b.brand + '@' + b.version);
    const brandStr = brands.join(', ');
    rows.push(['UA-CH brands',               brandStr || '(empty)', 'cyan']);
    const hasEdgeBrand = brands.some(b => b.includes('Microsoft Edge'));
    const hasChromeBrand = brands.some(b => b.includes('Google Chrome'));
    const hasChromiumBrand = brands.some(b => b.includes('Chromium'));
    rows.push(['Brand: Microsoft Edge',      yesno(hasEdgeBrand),    hasEdgeBrand    ? 'green' : 'dim']);
    rows.push(['Brand: Google Chrome',       yesno(hasChromeBrand),  hasChromeBrand  ? 'cyan'  : 'dim']);
    rows.push(['Brand: Chromium',            yesno(hasChromiumBrand),hasChromiumBrand? 'dim'   : '']);

    // Full high-entropy UA-CH (already done in §1 but we repeat Edge-specific ones)
    try {
      const hints = await n.userAgentData.getHighEntropyValues(['architecture','bitness','model','wow64']);
      rows.push(['CH: architecture',         hints.architecture || '—', 'purple']);
      rows.push(['CH: bitness',              hints.bitness || '—',      'purple']);
      rows.push(['CH: model (OEM name)',     hints.model || '(blank — desktop)', '']);
      rows.push(['CH: wow64 (32-on-64)',     String(hints.wow64), hints.wow64 ? 'yellow' : '']);
    } catch(e) {
      rows.push(['UA-CH high-entropy',       '(error: ' + e.message + ')', 'red']);
    }
  } else {
    rows.push(['UA-CH API (navigator.userAgentData)', tag('NOT PRESENT','no'), 'dim']);
  }

  /* ── Legacy IE / EdgeHTML DOM properties ───────────────────────────────── */
  const docMode = doc.documentMode;
  rows.push(['document.documentMode (IE)',    docMode != null ? String(docMode) : tag('undefined','dim'),
    docMode != null ? 'red' : '']);
  rows.push(['window.MSStream (IE/old Edge)', yesno(typeof w.MSStream !== 'undefined'),
    typeof w.MSStream !== 'undefined' ? 'yellow' : '']);
  rows.push(['window.msCrypto (IE11)',        yesno(typeof w.msCrypto !== 'undefined'),
    typeof w.msCrypto !== 'undefined' ? 'yellow' : '']);
  rows.push(['window.msRequestAnimationFrame',yesno(typeof w.msRequestAnimationFrame !== 'undefined'), '']);
  rows.push(['window.MSPointerEvent',         yesno(typeof w.MSPointerEvent !== 'undefined'), '']);
  rows.push(['window.external.msIsSiteMode', (()=>{
    try { return yesno(typeof w.external !== 'undefined' && typeof w.external.msIsSiteMode === 'function'); }
    catch(e) { return tag('blocked','warn'); }
  })(), '']);
  rows.push(['window.msWriteProfilerMark',   yesno(typeof w.msWriteProfilerMark !== 'undefined'), '']);

  /* ── window.chrome — Chrome and Chromium Edge both expose this ──────── */
  rows.push(['window.chrome object',          yesno(typeof w.chrome !== 'undefined'),
    typeof w.chrome !== 'undefined' ? 'green' : 'dim']);
  if (w.chrome) {
    rows.push(['chrome.runtime',              yesno(!!w.chrome.runtime), '']);
    rows.push(['chrome.csi() (timing)',       yesno(typeof w.chrome.csi === 'function'), '']);
    rows.push(['chrome.loadTimes() (legacy)', yesno(typeof w.chrome.loadTimes === 'function'), '']);
    rows.push(['chrome.webstore (deprecated)',yesno(!!w.chrome.webstore), '']);
    rows.push(['chrome.app',                  yesno(!!w.chrome.app), '']);
  }

  /* ── Edge-exclusive PWA / Shell APIs ───────────────────────────────────── */
  rows.push(['navigator.windowControlsOverlay',
    typeof n.windowControlsOverlay !== 'undefined'
      ? (n.windowControlsOverlay.visible ? 'visible (PWA window mode)' : 'present but hidden')
      : tag('undefined','dim'),
    typeof n.windowControlsOverlay !== 'undefined' ? 'yellow' : '']);

  // Window Management API (Edge/Chrome 100+)
  rows.push(['window.getScreenDetails (Window Mgmt)', yesno(typeof w.getScreenDetails === 'function'),
    typeof w.getScreenDetails === 'function' ? 'green' : '']);

  // Web App launch queue (Edge + Chrome desktop PWA)
  rows.push(['window.launchQueue (PWA Launch Handler)', yesno(typeof w.launchQueue !== 'undefined'), '']);

  // File Handling API
  rows.push(['window.launchParams',           yesno(typeof w.launchParams !== 'undefined'), '']);

  // Protocol Handler API
  rows.push(['navigator.registerProtocolHandler', yesno(typeof n.registerProtocolHandler === 'function'), '']);

  // Compute Pressure API (Edge/Chrome 115+)
  rows.push(['PressureObserver (Compute Pressure)', yesno(typeof w.PressureObserver !== 'undefined'),
    typeof w.PressureObserver !== 'undefined' ? 'green' : '']);

  // Document Picture-in-Picture (Chrome/Edge 116+)
  rows.push(['documentPictureInPicture API', yesno(typeof w.documentPictureInPicture !== 'undefined'), '']);

  // Speculation Rules API (Chrome/Edge 109+)
  rows.push(['HTMLScriptElement.supports() — speculationrules',
    (()=>{
      try { return yesno(HTMLScriptElement.supports && HTMLScriptElement.supports('speculationrules')); }
      catch(e) { return tag('error','warn'); }
    })(), '']);

  // Fenced Frames (Privacy Sandbox, Chrome/Edge only)
  rows.push(['HTMLFencedFrameElement',        yesno(typeof w.HTMLFencedFrameElement !== 'undefined'), '']);

  // OPFS (Origin Private File System)
  rows.push(['navigator.storage.getDirectory (OPFS)',
    yesno(n.storage && typeof n.storage.getDirectory === 'function'), '']);

  // Topics API (Privacy Sandbox)
  rows.push(['document.browsingTopics (Topics API)',
    yesno(typeof doc.browsingTopics === 'function'), '']);

  // Attribution Reporting API
  rows.push(['window.attributionReporting',   yesno(typeof w.attributionReporting !== 'undefined'), '']);

  // ink() API (stylus/inking) — Edge-specific first, Chrome 94+
  rows.push(['navigator.ink (Ink API)',        yesno(typeof n.ink !== 'undefined'),
    typeof n.ink !== 'undefined' ? 'yellow' : '']);

  /* ── CSS -ms- feature detection ─────────────────────────────────────── */
  function cssSup(p, v) { return !!(CSS && CSS.supports && CSS.supports(p, v)); }

  rows.push(['CSS -ms-overflow-style',        yesno(cssSup('-ms-overflow-style','none')), '']);
  rows.push(['CSS -ms-high-contrast (legacy)',yesno(cssSup('-ms-high-contrast','none')), '']);
  rows.push(['CSS overscroll-behavior',       yesno(cssSup('overscroll-behavior','none')), '']); // MS-first
  rows.push(['CSS scrollbar-gutter',          yesno(cssSup('scrollbar-gutter','stable')), '']);
  rows.push(['CSS accent-color',              yesno(cssSup('accent-color','red')), '']);
  rows.push(['CSS zoom (non-standard)',       yesno(cssSup('zoom','1')), 'yellow']);

  /* ── Edge media codec probes ─────────────────────────────────────────── */
  const vi = doc.createElement('video');
  const canPlay = (t) => { try { return vi.canPlayType(t) || tag('no','no'); } catch(e) { return 'error'; } };
  rows.push(['video/mp4; codecs=hvc1 (HEVC on Edge/Win)',
    canPlay('video/mp4; codecs=hvc1'), '']);
  rows.push(['video/mp4; codecs=av01 (AV1 on Edge/Win)',
    canPlay('video/mp4; codecs=av01.0.05M.08'), '']);
  rows.push(['video/webm; codecs=vp09 (VP9)',
    canPlay('video/webm; codecs=vp09.00.10.08'), '']);

  /* ── Confidence score ───────────────────────────────────────────────── */
  const edgeSigs = [isEdge, isEdgeHTML, typeof w.chrome !== 'undefined',
    !!n.userAgentData, typeof n.windowControlsOverlay !== 'undefined'].filter(Boolean);
  const edgeConf = Math.round((edgeSigs.length / 5) * 100);
  rows.push(['Edge/Chromium confidence score', edgeConf + '%',
    edgeConf > 60 ? 'green' : edgeConf > 30 ? 'yellow' : 'dim']);

  FP.edge = String(edgeConf) + '|' + (edgeVerMatch ? edgeVerMatch[1] : '') + '|' + (chromeVerMatch ? chromeVerMatch[1] : '');
  renderRows('body-edge', rows, 'cnt-edge');

  if (edgeConf > 40) addStatusChip('🔷 Edge: ' + edgeConf + '%', 'ok');
}

/* ═══════════════════════════════════════════════════════════════════════════
   §24  FIREFOX / GECKO-SPECIFIC
   Covers Firefox, Firefox ESR, Firefox for Android, Waterfox, LibreWolf,
   Tor Browser (Firefox-based), Pale Moon (Goanna / Gecko fork).
═══════════════════════════════════════════════════════════════════════════ */
async function collectFirefox() {
  setProgress(95, 'Running Firefox/Gecko probes...');
  const rows = [];
  const w   = window;
  const n   = navigator;
  const ua  = n.userAgent;
  const doc = document;

  /* ── UA string dissection ─────────────────────────────────────────────── */
  const isFirefox      = /Firefox\//.test(ua);
  const isGecko        = /Gecko\//.test(ua) && !/like Gecko/.test(ua.split('Gecko/')[1] || '');
  const isTorBrowser   = /Firefox\//.test(ua) && /[\s;]rv:/.test(ua);
  const isLibreWolf    = /LibreWolf/.test(ua);
  const isWaterfox     = /Waterfox/.test(ua);
  const isPaleMoon     = /PaleMoon|Goanna/.test(ua);
  const ffVerMatch     = ua.match(/Firefox\/([\d.]+)/);
  const geckoVerMatch  = ua.match(/rv:([\d.]+)/);
  const geckoDateMatch = ua.match(/Gecko\/(20\d{6}|\d+\.\d+)/);

  rows.push(['UA: Firefox',                  yesno(isFirefox),    isFirefox   ? 'green'  : 'dim']);
  rows.push(['UA: Gecko (not "like Gecko")', yesno(isGecko),      isGecko     ? 'green'  : 'dim']);
  rows.push(['UA: LibreWolf',                yesno(isLibreWolf),  isLibreWolf ? 'yellow' : 'dim']);
  rows.push(['UA: Waterfox',                 yesno(isWaterfox),   isWaterfox  ? 'yellow' : 'dim']);
  rows.push(['UA: Pale Moon / Goanna',       yesno(isPaleMoon),   isPaleMoon  ? 'yellow' : 'dim']);
  rows.push(['Firefox version',             ffVerMatch   ? ffVerMatch[1]   : '(not in UA)', ffVerMatch   ? 'yellow' : '']);
  rows.push(['Gecko rv: version',           geckoVerMatch? geckoVerMatch[1]: '(not in UA)', '']);
  rows.push(['Gecko build date',            geckoDateMatch? geckoDateMatch[1]: '(not in UA)', '']);

  /* ── Tier A: Definitive Gecko/Firefox-only properties ──────────────── */

  // navigator.buildID — Firefox only (used to expose exact build timestamp)
  const buildID = n.buildID;
  rows.push(['navigator.buildID (Gecko-only)',
    buildID ? buildID : tag('undefined — not Firefox','dim'),
    buildID ? 'green' : '']);

  // navigator.oscpu — only Firefox exposes the real CPU string
  const oscpu = n.oscpu;
  rows.push(['navigator.oscpu (Gecko-only)',
    oscpu ? oscpu : tag('undefined — not Firefox','dim'),
    oscpu ? 'green' : '']);

  // window.sidebar — Firefox (and Netscape heritage) only
  rows.push(['window.sidebar (Firefox/Netscape)', yesno(typeof w.sidebar !== 'undefined'),
    typeof w.sidebar !== 'undefined' ? 'yellow' : '']);

  // window.netscape — Netscape/Firefox legacy
  rows.push(['window.netscape (Netscape/FF legacy)', yesno(typeof w.netscape !== 'undefined'),
    typeof w.netscape !== 'undefined' ? 'yellow' : '']);

  // window.Components — Firefox privileged JS (chrome context only)
  rows.push(['window.Components (Firefox XUL/priv.)', yesno(typeof w.Components !== 'undefined'),
    typeof w.Components !== 'undefined' ? 'red' : '']); // red = highly elevated context

  // window.controllers — XUL controllers
  rows.push(['window.controllers (Firefox XUL)',  yesno(typeof w.controllers !== 'undefined'), '']);

  // InstallTrigger — the canonical Firefox detector (being removed but still present in ESR)
  rows.push(['window.InstallTrigger (Firefox canonical)', yesno(typeof w.InstallTrigger !== 'undefined'),
    typeof w.InstallTrigger !== 'undefined' ? 'green' : '']);

  // mozIndexedDB / mozRTCPeerConnection (old prefixes)
  rows.push(['window.mozIndexedDB',          yesno(typeof w.mozIndexedDB !== 'undefined'), '']);
  rows.push(['window.mozRTCPeerConnection',  yesno(typeof w.mozRTCPeerConnection !== 'undefined'), '']);
  rows.push(['window.mozRTCSessionDescription', yesno(typeof w.mozRTCSessionDescription !== 'undefined'), '']);
  rows.push(['window.mozRTCIceCandidate',    yesno(typeof w.mozRTCIceCandidate !== 'undefined'), '']);

  // MozMutationObserver
  rows.push(['window.MozMutationObserver',   yesno(typeof w.MozMutationObserver !== 'undefined'), '']);

  // document Moz-prefixed fullscreen
  rows.push(['document.mozFullScreenElement',yesno(typeof doc.mozFullScreenElement !== 'undefined'), '']);
  rows.push(['document.mozFullScreen',       yesno(typeof doc.mozFullScreen !== 'undefined'), '']);

  // element.mozMatchesSelector
  const divEl = doc.createElement('div');
  rows.push(['element.mozMatchesSelector',   yesno(typeof divEl.mozMatchesSelector === 'function'), '']);

  // navigator.taintEnabled — removed in FF65+ but still detectable as undefined vs function
  rows.push(['navigator.taintEnabled (pre-FF65)', yesno(typeof n.taintEnabled === 'function'), '']);

  // navigator.mozIsLocallyAvailable — old Firefox DOM
  rows.push(['navigator.mozIsLocallyAvailable', yesno(typeof n.mozIsLocallyAvailable === 'function'), '']);

  /* ── CSS -moz- feature support ──────────────────────────────────────── */
  function cssSup(p, v) { return !!(CSS && CSS.supports && CSS.supports(p, v)); }

  rows.push(['CSS -moz-appearance: none',   yesno(cssSup('-moz-appearance','none')),      typeof w.InstallTrigger !== 'undefined' ? 'green' : '']);
  rows.push(['CSS display: -moz-box',        yesno(cssSup('display','-moz-box')), '']);
  rows.push(['CSS display: -moz-inline-box', yesno(cssSup('display','-moz-inline-box')), '']);
  rows.push(['CSS -moz-osx-font-smoothing',  yesno(cssSup('-moz-osx-font-smoothing','grayscale')), '']);
  rows.push(['CSS scrollbar-width: thin',    yesno(cssSup('scrollbar-width','thin')),   '']); // Firefox-first, now wider
  rows.push(['CSS scrollbar-color',          yesno(cssSup('scrollbar-color','red blue')),'']); // Firefox-first
  rows.push(['CSS image-rendering: -moz-crisp-edges', yesno(cssSup('image-rendering','-moz-crisp-edges')), '']);
  rows.push(['CSS -moz-text-decoration-color', yesno(cssSup('-moz-text-decoration-color','red')), '']);
  rows.push(['CSS text-decoration-skip-ink', yesno(cssSup('text-decoration-skip-ink','auto')), '']); // FF first

  /* ── Firefox canvas RFP (Resist Fingerprinting) detection ──────────── */
  // When privacy.resistFingerprinting = true, Firefox adds noise to
  // canvas reads. Also clamps screen size and timezone to UTC.
  const rfpCanvas = doc.createElement('canvas');
  rfpCanvas.width = 100; rfpCanvas.height = 1;
  const rfpCtx = rfpCanvas.getContext('2d');
  rfpCtx.fillStyle = 'rgba(123, 45, 67, 0.89)';
  rfpCtx.fillRect(0, 0, 100, 1);
  const rfpPx = rfpCtx.getImageData(50, 0, 1, 1).data;
  // Exact expected RGBA for the alpha-blended colour on white background:
  // R = round(123*0.89 + 255*0.11) = round(109.47+28.05) = 138
  // G = round(45*0.89 + 255*0.11) = round(40.05+28.05) = 68
  // B = round(67*0.89 + 255*0.11) = round(59.63+28.05) = 88
  const rfpExpected = [138, 68, 88, 255];
  const rfpNoise = rfpPx[0] !== rfpExpected[0] || rfpPx[1] !== rfpExpected[1] || rfpPx[2] !== rfpExpected[2];
  rows.push(['Firefox RFP: canvas noise detected', yesno(rfpNoise),
    rfpNoise ? 'yellow' : '']);
  rows.push(['RFP pixel got',
    `rgba(${rfpPx[0]},${rfpPx[1]},${rfpPx[2]},${rfpPx[3]})`, 'dim']);
  rows.push(['RFP pixel expected',
    `rgba(${rfpExpected.join(',')})`, 'dim']);

  // RFP timezone clamping — FF RFP forces timezone to UTC
  const tzRFP = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const tzIsUTC = tzRFP === 'UTC' || tzRFP === 'Etc/UTC';
  rows.push(['RFP: timezone forced to UTC', yesno(tzIsUTC),
    tzIsUTC ? 'yellow' : '']);

  // RFP screen clamping — FF RFP reports 1366×768 regardless of real res
  const screenRFP = screen.width === 1366 && screen.height === 768;
  rows.push(['RFP: screen clamped to 1366×768', yesno(screenRFP),
    screenRFP ? 'yellow' : '']);

  // RFP hardwareConcurrency forced to 2
  const hwRFP = n.hardwareConcurrency === 2;
  rows.push(['RFP: hardwareConcurrency forced to 2', yesno(hwRFP), hwRFP ? 'yellow' : '']);

  // Overall RFP verdict
  const rfpScore = [rfpNoise, tzIsUTC, screenRFP, hwRFP].filter(Boolean).length;
  rows.push(['Firefox RFP active estimate', rfpScore >= 2 ? tag('LIKELY ACTIVE ('+rfpScore+'/4 signals)','warn') : tag('probably OFF ('+rfpScore+'/4)','item'), '']);

  /* ── Firefox-specific Media / codec probes ───────────────────────────── */
  const au = doc.createElement('audio');
  const vi = doc.createElement('video');
  const canPlay = (el, t) => { try { return el.canPlayType(t) || tag('no','no'); } catch(e) { return 'error'; } };

  rows.push(['audio/ogg; codecs=vorbis',     canPlay(au,'audio/ogg; codecs=vorbis'), '']); // FF-primary
  rows.push(['audio/ogg; codecs=opus',       canPlay(au,'audio/ogg; codecs=opus'), 'green']);
  rows.push(['audio/ogg; codecs=flac',       canPlay(au,'audio/ogg; codecs=flac'), '']);
  rows.push(['video/ogg; codecs=theora',     canPlay(vi,'video/ogg; codecs=theora'), '']); // FF heritage
  rows.push(['video/webm; codecs=vp8,vorbis',canPlay(vi,'video/webm; codecs=vp8,vorbis'), '']);
  rows.push(['video/webm; codecs=vp9',       canPlay(vi,'video/webm; codecs=vp9'), '']);
  rows.push(['video/webm; codecs=av1',       canPlay(vi,'video/webm; codecs=av01.0.05M.08'), '']);
  // HEVC / H.265 — NOT supported in Firefox without external codec
  rows.push(['video/mp4; codecs=hvc1 (HEVC — FF usually no)',
    canPlay(vi,'video/mp4; codecs=hvc1'), '']);

  /* ── Firefox-exclusive newer APIs ───────────────────────────────────── */
  // showPickerFor / custom media controls (under development)
  rows.push(['HTMLInputElement.showPicker',  yesno(typeof doc.createElement('input').showPicker === 'function'), '']);

  // Sanitizer API (Firefox 83+ behind flag, Chrome 105+)
  rows.push(['Sanitizer API',                yesno(typeof w.Sanitizer !== 'undefined'), '']);

  // File System Access (Firefox ships a partial impl via showOpenFilePicker)
  rows.push(['showOpenFilePicker (FSAA)',     yesno(typeof w.showOpenFilePicker === 'function'), '']);

  // Profiler API — Firefox DevTools hook
  rows.push(['window.Profiler (FF DevTools)',yesno(typeof w.Profiler !== 'undefined'), '']);

  // navigator.getAutoplayPolicy (Firefox 112+)
  rows.push(['navigator.getAutoplayPolicy',  yesno(typeof n.getAutoplayPolicy === 'function'),
    typeof n.getAutoplayPolicy === 'function' ? 'yellow' : '']);

  /* ── Confidence score ───────────────────────────────────────────────── */
  const ffSigs = [isFirefox, !!buildID, !!oscpu, typeof w.sidebar !== 'undefined',
    typeof w.InstallTrigger !== 'undefined', cssSup('-moz-appearance','none')].filter(Boolean);
  const ffConf = Math.round((ffSigs.length / 6) * 100);
  rows.push(['Firefox/Gecko confidence score', ffConf + '%',
    ffConf > 60 ? 'green' : ffConf > 30 ? 'yellow' : 'dim']);

  FP.firefox = String(ffConf) + '|' + (ffVerMatch ? ffVerMatch[1] : '') + '|' + (oscpu || '') + '|rfp:' + rfpScore;
  renderRows('body-firefox', rows, 'cnt-firefox');

  if (ffConf > 40) addStatusChip('🦊 Firefox: ' + ffConf + '%', 'ok');
}


/* ═══════════════════════════════════════════════════════════════════════════
   LIGHT / DARK THEME TOGGLE
═══════════════════════════════════════════════════════════════════════════ */
function toggleTheme() {
  // Toggle on <html> — most reliable for CSS custom property inheritance
  // across all browsers including iOS Safari / WebKit
  const root  = document.documentElement;
  const icon  = document.getElementById('theme-icon');
  const label = document.getElementById('theme-label');
  root.classList.toggle('light');
  const isLight = root.classList.contains('light');
  icon.textContent  = isLight ? '🌙' : '☀';
  label.textContent = isLight ? 'dark' : 'light';
  try { localStorage.setItem('bp-theme', isLight ? 'light' : 'dark'); } catch(e) {}
}
// Restore saved preference on load
(function() {
  try {
    if (localStorage.getItem('bp-theme') === 'light') {
      document.documentElement.classList.add('light');
      // DOM not ready yet for button text; handled after DOMContentLoaded
    }
  } catch(e) {}
})();

/* ═══════════════════════════════════════════════════════════════════════════
   INTELLIGENCE SUMMARY BAR
   Synthesises all collected FP signals into human-readable best-guess cells.
   Each cell gets a confidence class: 'high' | 'medium' | 'low' | 'none'
   rendered as a 3px coloured underline strip.
═══════════════════════════════════════════════════════════════════════════ */
function computeSummaryBar() {
  const ua  = navigator.userAgent;
  const n   = navigator;
  const w   = window;

  // Helper: set one intel cell
  function setCell(id, value, sub, conf) {
    document.getElementById('iv-' + id).textContent = value || '—';
    document.getElementById('is-' + id).textContent = sub   || '\u00a0';
    const strip = document.getElementById('iconf-' + id);
    strip.className = 'intel-conf ' + (conf || 'none');
  }

  /* ── 1. BROWSER ─────────────────────────────────────────────────────── */
  (function() {
    let name = '?', ver = '', conf = 'low';

    // UA-CH brand list is the gold standard (Chromium only)
    if (n.userAgentData && n.userAgentData.brands) {
      const brands = n.userAgentData.brands;
      // Find the most specific brand (not "Not A Brand" / "Chromium")
      const prio = brands.filter(b =>
        !/Not.A.Brand|Chromium/i.test(b.brand) && b.brand.trim() !== ''
      );
      if (prio.length) {
        name = prio[0].brand;
        ver  = 'v' + prio[0].version;
        conf = 'high';
      } else {
        // Only Chromium brand present — generic Chromium build
        const ch = brands.find(b => /Chromium/i.test(b.brand));
        if (ch) { name = 'Chromium'; ver = 'v' + ch.version; conf = 'medium'; }
      }
    }

    // Firefox — buildID is definitive
    if (typeof n.buildID !== 'undefined' && n.buildID) {
      const ffM = ua.match(/Firefox\/([\d.]+)/);
      name = 'Firefox'; ver = ffM ? 'v' + ffM[1] : ''; conf = 'high';
      // Forks
      if (/LibreWolf/i.test(ua)) { name = 'LibreWolf'; conf = 'high'; }
      if (/Waterfox/i.test(ua))  { name = 'Waterfox';  conf = 'high'; }
      if (/PaleMoon/i.test(ua))  { name = 'Pale Moon'; conf = 'high'; }
    }

    // Safari — window.safari and no Chrome in UA
    if (typeof w.safari !== 'undefined' && !/Chrome/.test(ua)) {
      const sfM = ua.match(/Version\/([\d.]+).*Safari/);
      name = 'Safari'; ver = sfM ? 'v' + sfM[1] : ''; conf = 'high';
      if (/Mobile.*Safari|iPhone|iPad|iPod/.test(ua)) name = 'Mobile Safari';
    }

    // Fallback: UA regex parse
    if (name === '?' || name === 'Chromium') {
      const matchers = [
        [/OPR\/([\d.]+)/,      'Opera',         'medium'],
        [/Vivaldi\/([\d.]+)/,  'Vivaldi',        'high'],
        [/YaBrowser\/([\d.]+)/,'Yandex Browser', 'high'],
        [/Brave/,              'Brave',          'medium'],
        [/Edg\/([\d.]+)/,      'Edge',           'high'],
        [/Chrome\/([\d.]+)/,   'Chrome',         'medium'],
        [/Firefox\/([\d.]+)/,  'Firefox',        'medium'],
        [/Safari\/([\d.]+)/,   'Safari',         'medium'],
        [/MSIE ([\d.]+)/,      'Internet Explorer','high'],
        [/Trident.*rv:([\d.]+)/,'Internet Explorer','high'],
      ];
      for (const [re, n2, c] of matchers) {
        const m = ua.match(re);
        if (m) {
          if (name === '?' || c === 'high') {
            name = n2;
            ver  = m[1] ? 'v' + m[1].split('.')[0] : '';
            conf = c;
          }
          break;
        }
      }
    }

    // Special: Brave exposes navigator.brave
    if (n.brave && typeof n.brave.isBrave === 'function') {
      name = 'Brave'; ver = ''; conf = 'high';
    }

    setCell('browser', name, ver, conf);
  })();

  /* ── 2. ENGINE ──────────────────────────────────────────────────────── */
  (function() {
    let engine = '?', ver = '', conf = 'low';

    // Gecko: buildID + oscpu = definitive
    if (typeof n.buildID !== 'undefined' && n.buildID) {
      engine = 'Gecko';
      const rv = ua.match(/rv:([\d.]+)/);
      ver = rv ? 'rv:' + rv[1] : '';
      conf = 'high';
    }
    // WebKit (not Chromium)
    else if (/WebKit/.test(ua) && !/Chrome/.test(ua)) {
      const wk = ua.match(/AppleWebKit\/([\d.]+)/);
      engine = 'WebKit';
      ver = wk ? wk[1] : '';
      conf = 'high';
    }
    // Blink (Chrome/Edge/Opera etc.)
    else if (/Chrome/.test(ua)) {
      const wk = ua.match(/AppleWebKit\/([\d.]+)/);
      engine = 'Blink';
      ver = wk ? '(wk ' + wk[1] + ')' : '';
      conf = n.userAgentData ? 'high' : 'medium';
    }
    // Trident (IE)
    else if (/Trident/.test(ua)) {
      const tr = ua.match(/Trident\/([\d.]+)/);
      engine = 'Trident';
      ver = tr ? tr[1] : '';
      conf = 'high';
    }
    // EdgeHTML
    else if (/Edge\//.test(ua)) {
      const eh = ua.match(/Edge\/([\d.]+)/);
      engine = 'EdgeHTML';
      ver = eh ? eh[1] : '';
      conf = 'high';
    }

    setCell('engine', engine, ver, conf);
  })();

  /* ── 3. OPERATING SYSTEM ───────────────────────────────────────────────
   Signal priority:
     1. navigator.platform  — set by JS engine, rarely spoofed
     2. navigator.userAgentData (UA-CH)  — Chromium high-entropy
     3. navigator.oscpu  — Firefox only
     4. UA regex  — lowest trust; Chromium fakes "X11; Linux x86_64" on Android
   ─────────────────────────────────────────────────────────────────────── */
  (function() {
    let os = '?', ver = '', conf = 'low';
    const plat = n.platform || '';  // e.g. "Linux armv81", "iPhone", "Win32", "MacIntel"

    // platform directly tells us OS family in many cases
    if (/iPhone|iPod/.test(plat))         { os = 'iOS';      conf = 'high'; }
    else if (/iPad/.test(plat))           { os = 'iPadOS';   conf = 'high'; }
    else if (/MacIntel|MacPPC/.test(plat)){ os = 'macOS';    conf = 'medium'; }
    else if (/Win/.test(plat))            { os = 'Windows';  conf = 'medium'; }
    else if (/Linux/.test(plat))          { os = 'Linux';    conf = 'medium'; } // could be Android

    // UA-CH platform is the most reliable version source for Chromium
    if (FP.uaCH) {
      try {
        const hints = JSON.parse(FP.uaCH);
        if (hints.platform) {
          // Upgrade confidence only if it agrees with platform or adds new info
          const hintPlatform = hints.platform.toLowerCase();
          if (/win/i.test(hintPlatform)) {
            os = 'Windows'; conf = 'high';
            if (hints.platformVersion) {
              const [major] = hints.platformVersion.split('.');
              ver = (+major >= 13) ? 'v11+' : (+major >= 10) ? 'v10' : 'v8/8.1';
            }
          } else if (/macos|mac os/i.test(hintPlatform)) {
            os = 'macOS'; conf = 'high';
            if (hints.platformVersion) ver = hints.platformVersion.split('.').slice(0,2).join('.');
          } else if (/android/i.test(hintPlatform)) {
            os = 'Android'; conf = 'high';
            if (hints.platformVersion) ver = hints.platformVersion;
          } else if (/chromeos|cros/i.test(hintPlatform)) {
            os = 'ChromeOS'; conf = 'high';
          } else if (/linux/i.test(hintPlatform) && os === 'Linux') {
            conf = 'medium'; // UA-CH confirms Linux but doesn't help differentiate Android
          }
        }
      } catch(e) {}
    }

    // navigator.oscpu — Firefox; very precise
    if (n.oscpu && os === '?') {
      os = n.oscpu.split(' ').slice(0,2).join(' '); conf = 'high';
    }

    // UA regex — last resort, treated as medium at best
    if (os === '?' || os === 'Linux') {
      const prevOs = os;
      // Android check before Linux — "Android" appears in UA even when platform says Linux
      if (/Android ([\d.]+)/i.test(ua)) {
        os = 'Android';
        ver = ver || RegExp.$1.split('.').slice(0,2).join('.');
        conf = 'high';  // Android is explicit in UA, unlike desktop Linux
      } else if (os === '?') {
        const uaOS = [
          [/Windows NT 10\.0/, 'Windows', 'v10/11', 'medium'],
          [/Windows NT 6\.3/,  'Windows', 'v8.1',   'medium'],
          [/Windows NT 6\.2/,  'Windows', 'v8',     'medium'],
          [/Windows NT 6\.1/,  'Windows', 'v7',     'medium'],
          [/iPad.*OS ([\d_]+)/,'iPadOS',  '',        'high'],
          [/iPhone.*OS ([\d_]+)/,'iOS',   '',        'high'],
          [/Mac OS X ([\d_]+)/,'macOS',   '',        'medium'],
          [/CrOS/,             'ChromeOS','',        'medium'],
        ];
        for (const [re, name2, v2, c] of uaOS) {
          const m2 = ua.match(re);
          if (m2) {
            os = name2;
            ver = v2 || (m2[1] ? m2[1].replace(/_/g,'.').split('.').slice(0,2).join('.') : '');
            conf = c; break;
          }
        }
      }
    }

    setCell('os', os, ver, conf);
  })();

  /* ── 4. ARCHITECTURE ────────────────────────────────────────────────────
   * Signal reliability ranking (learned from real-world misdetection):
   *
   * MOST RELIABLE:
   *   navigator.platform  — JS engine sets this from actual syscall, very
   *                         hard to spoof; "Linux armv81" is ground truth.
   *   GPU renderer        — Mali/Adreno/PowerVR = ARM.  Intel/NVIDIA/AMD = x86.
   *                         Hardware doesn't lie about itself.
   *
   * MEDIUM:
   *   UA-CH architecture  — Correct on desktop Chrome/Edge.  Unreliable on
   *                         Android Chromium forks which may inherit the
   *                         Windows/desktop UA-CH shim and report "x86".
   *   navigator.oscpu     — Firefox only but precise when present.
   *
   * LEAST RELIABLE:
   *   UA string           — Chromium on Android routinely sets
   *                         "Linux x86_64" to maximise site compatibility.
   *                         Treat as a last resort only.
   *
   * Conflict detection: when platform/GPU disagree with UA-CH/UA, we flag
   * the conflict, prefer the hardware signals, and lower confidence.
   * ─────────────────────────────────────────────────────────────────────── */
  (function() {
    let arch = '?', sub = '', conf = 'low';
    const plat = n.platform || '';

    // ── Signal 1: navigator.platform ─────────────────────────────────────
    // This is the single most reliable source. The JS engine populates it
    // from the OS uname() syscall result, not from any UA string.
    let platArch = '?';
    if (/armv8|aarch64|arm64/i.test(plat))              platArch = 'ARM64';
    else if (/armv7|armv6|armv5/i.test(plat))           platArch = 'ARM32';
    else if (/arm/i.test(plat) && /64/.test(plat))      platArch = 'ARM64';
    else if (/arm/i.test(plat))                         platArch = 'ARM';
    else if (/x86_64|x86-64|amd64/i.test(plat))        platArch = 'x86-64';
    else if (/i[3-6]86|x86_32/i.test(plat))             platArch = 'x86-32';
    else if (/Win64/i.test(plat))                       platArch = 'x86-64';
    else if (/Win32/i.test(plat))                       platArch = 'x86 (32/64)'; // Win32 = API, not bitness
    else if (/iPhone|iPad|iPod/.test(plat))             platArch = 'ARM64';
    else if (/MacIntel/.test(plat))                     platArch = 'x86-64'; // may be Rosetta
    else if (/MacPPC/.test(plat))                       platArch = 'PowerPC';

    // ── Signal 2: GPU renderer cross-check ───────────────────────────────
    // GPU vendor is a hardware-level signal that cannot be spoofed by UA.
    let gpuArch = '?';
    const gpuStr = (FP.gpuRenderer || '') + ' ' + (FP.gpuVendor || '');
    if (/Mali/i.test(gpuStr))                           gpuArch = 'ARM';   // ARM Mali → always ARM SoC
    else if (/Adreno/i.test(gpuStr))                    gpuArch = 'ARM';   // Qualcomm Adreno → ARM
    else if (/PowerVR/i.test(gpuStr))                   gpuArch = 'ARM';   // Imagination → ARM
    else if (/Apple (GPU|M[0-9])/i.test(gpuStr))        gpuArch = 'ARM64'; // Apple Silicon
    else if (/NVIDIA|GeForce|Quadro/i.test(gpuStr))     gpuArch = 'x86';   // discrete GPU → x86 host
    else if (/Intel.*((U?HD|Iris|Arc)|Graphics)/i.test(gpuStr)) gpuArch = 'x86';
    else if (/AMD|Radeon/i.test(gpuStr) && !/Mali/i.test(gpuStr)) gpuArch = 'x86';

    // ── Signal 3: UA-CH (medium trust on non-desktop) ────────────────────
    let uachArch = '?';
    if (FP.uaCH) {
      try {
        const hints = JSON.parse(FP.uaCH);
        if (hints.architecture) {
          const a = hints.architecture, b = hints.bitness || '';
          if (/arm/i.test(a))                            uachArch = b === '64' ? 'ARM64' : 'ARM32';
          else if (/x86/i.test(a) && b === '64')         uachArch = 'x86-64';
          else if (/x86/i.test(a))                       uachArch = 'x86-32';
          else                                           uachArch = a + (b ? '-'+b : '');
        }
      } catch(e) {}
    }

    // ── Signal 4: navigator.oscpu (Firefox only) ─────────────────────────
    let oscpuArch = '?';
    if (n.oscpu) {
      if (/x86_64|x86-64|amd64/i.test(n.oscpu))        oscpuArch = 'x86-64';
      else if (/i[3-6]86/i.test(n.oscpu))               oscpuArch = 'x86-32';
      else if (/aarch64|arm64/i.test(n.oscpu))          oscpuArch = 'ARM64';
      else if (/armv/i.test(n.oscpu))                   oscpuArch = 'ARM32';
    }

    // ── Signal 5: UA string (lowest trust — explicitly last) ──────────────
    let uaArch = '?';
    if (/Win64|WOW64/i.test(ua))                        uaArch = 'x86-64';
    else if (/x86_64|x86-64|amd64/i.test(ua))           uaArch = 'x86-64';  // NOTE: Chromium-Android spoofs this
    else if (/ARM|aarch64/i.test(ua))                   uaArch = 'ARM64';
    else if (/Win32/i.test(ua))                         uaArch = 'x86 (32/64)';

    // ── Adjudication: prefer hardware signals, detect conflicts ───────────
    const conflicts = [];

    // Start from most reliable and work down
    if (platArch !== '?') {
      arch = platArch;
      conf = 'high';
      sub  = 'platform API';
    } else if (oscpuArch !== '?') {
      arch = oscpuArch;
      conf = 'high';
      sub  = 'oscpu (Firefox)';
    } else if (uachArch !== '?') {
      arch = uachArch;
      conf = 'medium';
      sub  = 'UA-CH hint';
    } else if (uaArch !== '?') {
      arch = uaArch;
      conf = 'low';
      sub  = 'UA string (unreliable)';
    }

    // GPU corroboration / conflict check
    if (gpuArch !== '?' && arch !== '?') {
      const gpuIsARM = gpuArch === 'ARM' || gpuArch === 'ARM64';
      const archIsARM = /ARM/i.test(arch);
      const gpuIsX86 = gpuArch === 'x86';
      const archIsX86 = /x86/i.test(arch);

      if ((gpuIsARM && archIsX86) || (gpuIsX86 && archIsARM)) {
        // Conflict! GPU says one thing, primary signal says another.
        // GPU is physical hardware — it wins on the ARM side.
        conflicts.push('GPU↔platform conflict');
        if (gpuIsARM && archIsX86) {
          // This is the Edge-on-Android case: platform is correct, UA-CH lied
          // but platArch already won above — this is the UA-CH vs platform conflict
          // If we got here via uachArch, override with GPU corroboration
          if (conf === 'medium' && uachArch !== '?' && platArch === '?') {
            arch = gpuArch.includes('64') ? 'ARM64' : 'ARM';
            conf = 'medium';
          }
        }
        sub = conflicts.join(' · ');
        // Conflicts reduce confidence
        if (conf === 'high')   conf = 'medium';
        else if (conf === 'medium') conf = 'low';
      } else {
        // GPU agrees — bump confidence slightly and note corroboration
        if (conf === 'medium' && gpuArch !== '?') conf = 'high';
        if (conf === 'low' && gpuArch !== '?')    conf = 'medium';
        const gpuNote = gpuIsARM ? 'GPU corroborates' : '';
        if (gpuNote && !sub.includes('corr')) sub = sub ? sub + ' · ' + gpuNote : gpuNote;
      }
    } else if (gpuArch !== '?' && arch === '?') {
      // Only GPU signal available
      arch = gpuArch;
      conf = 'low';
      sub  = 'GPU vendor only';
    }

    // Refine ARM32 vs ARM64 from GPU when ambiguous
    if (arch === 'ARM' && gpuArch === 'ARM64') arch = 'ARM64';

    // Rosetta 2 hint: MacIntel platform + Apple GPU = x86-64 binary on ARM64 host
    if (platArch === 'x86-64' && /Apple (GPU|M[0-9])/i.test(gpuStr)) {
      sub = 'Rosetta 2 (x86 binary on Apple Silicon)';
      conf = 'medium'; // can't tell if native arm64 app misreports
    }

    // wow64 hint from UA-CH
    if (FP.uaCH) {
      try {
        const hints = JSON.parse(FP.uaCH);
        if (hints.wow64) sub = (sub ? sub + ' · ' : '') + 'WoW64 (32-bit process on 64-bit OS)';
      } catch(e) {}
    }

    setCell('arch', arch || '?', sub, conf);
  })();

  /* ── 5. DEVICE TYPE ─────────────────────────────────────────────────────
   * Same multi-signal approach: pointer media queries + touch + UA + platform
   * ─────────────────────────────────────────────────────────────────────── */
  (function() {
    let dtype = '?', sub = '', conf = 'low';

    const touch     = n.maxTouchPoints > 0;
    const fine      = window.matchMedia('(pointer:fine)').matches;
    const coarse    = window.matchMedia('(pointer:coarse)').matches;
    const anyFine   = window.matchMedia('(any-pointer:fine)').matches;
    const anyCoarse = window.matchMedia('(any-pointer:coarse)').matches;
    const standalone = n.standalone;
    const plat      = n.platform || '';
    const mob       = /Mobile|Android.*Mobile|iPhone|iPod/i.test(ua);
    const tab       = /iPad|Tablet/i.test(ua) ||
                      (/iPad/.test(plat)) ||
                      (n.platform === 'MacIntel' && n.maxTouchPoints > 1); // iPadOS 13+

    // Check Android UA explicitly (some tablets omit "Tablet" keyword)
    const androidUA = /Android/i.test(ua);
    const androidMobile = androidUA && /Mobile/i.test(ua);
    const androidTablet = androidUA && !/Mobile/i.test(ua); // Android tablet convention

    if (/iPhone|iPod/.test(plat) || /iPhone|iPod/.test(ua)) {
      dtype = 'Mobile'; sub = 'iPhone'; conf = 'high';
    } else if (/iPad/.test(plat) || tab) {
      dtype = 'Tablet'; sub = 'iPad / iPadOS'; conf = 'high';
    } else if (androidTablet) {
      dtype = 'Tablet'; sub = 'Android tablet'; conf = 'high';
    } else if (androidMobile) {
      dtype = 'Mobile'; sub = 'Android phone'; conf = 'high';
    } else if (mob) {
      dtype = 'Mobile'; sub = 'mobile UA'; conf = 'medium';
    } else if (!touch && fine && !anyCoarse) {
      dtype = 'Desktop'; conf = 'high';
      if (/MacIntel|MacPPC/.test(plat))        sub = 'Mac';
      else if (/Win/.test(plat))               sub = 'PC';
      else if (/Linux/.test(plat) && !androidUA) sub = 'Linux workstation';
    } else if (touch && coarse && !fine && !anyFine) {
      dtype = 'Mobile/Tablet'; conf = 'medium'; sub = 'touch+coarse pointer';
    } else if (touch && fine) {
      dtype = 'Hybrid'; conf = 'medium'; sub = '2-in-1 (touch+fine pointer)';
    } else {
      dtype = 'Desktop'; conf = 'low'; sub = 'assumed';
    }

    // Pointer count hint
    if (n.maxTouchPoints > 0 && dtype !== '?')
      sub += sub ? ' · ' + n.maxTouchPoints + 'pt touch' : n.maxTouchPoints + 'pt touch';

    if (standalone) sub += sub ? ' · PWA' : 'PWA installed';

    setCell('device', dtype, sub, conf);
  })();


  /* ── 6. DISPLAY ─────────────────────────────────────────────────────── */
  (function() {
    const dpr  = window.devicePixelRatio || 1;
    const sw   = screen.width, sh = screen.height;
    const lw   = Math.round(sw / dpr), lh = Math.round(sh / dpr);

    // Colour gamut
    let gamut = 'sRGB', gamutConf = 'medium';
    if (window.matchMedia('(color-gamut:rec2020)').matches) { gamut = 'Rec.2020'; gamutConf = 'high'; }
    else if (window.matchMedia('(color-gamut:p3)').matches) { gamut = 'P3 wide';  gamutConf = 'high'; }

    // HDR
    const hdr = window.matchMedia('(dynamic-range:high)').matches;

    const value = sw + '×' + sh;
    const sub   = (dpr !== 1 ? dpr + 'x DPR · ' : '') + gamut + (hdr ? ' · HDR' : '');
    // Confidence: if DPR is a clean value and resolution is plausible, call it high
    const conf  = (dpr > 0 && sw > 0) ? 'high' : 'medium';

    setCell('display', value, sub, conf);
  })();

  /* ── 7. GPU / RENDERER ──────────────────────────────────────────────── */
  (function() {
    let gpu = '?', sub = '', conf = 'none';

    if (FP.gpuRenderer) {
      // Clean up the long Mesa / ANGLE strings
      let r = FP.gpuRenderer
        .replace(/ANGLE \(/, '')
        .replace(/\)$/, '')
        .replace(/Direct3D.*$/, '')
        .trim();

      // Extract brand from common patterns
      const vendor = FP.gpuVendor || '';
      if (/NVIDIA/i.test(r + vendor))      sub = 'NVIDIA';
      else if (/AMD|Radeon/i.test(r))      sub = 'AMD';
      else if (/Intel/i.test(r + vendor))  sub = 'Intel';
      else if (/Apple/i.test(r + vendor))  sub = 'Apple GPU';
      else if (/Adreno/i.test(r))          sub = 'Qualcomm';
      else if (/Mali/i.test(r))            sub = 'ARM Mali';
      else if (/PowerVR/i.test(r))         sub = 'PowerVR';
      else if (/llvmpipe|softpipe|swrast/i.test(r)) { sub = 'Software renderer'; }

      // Truncate to ~22 chars for the value slot
      gpu  = r.length > 24 ? r.substring(0, 22) + '…' : r;
      conf = 'high';
    } else if (FP.webglRender) {
      gpu  = 'WebGL (masked)';
      sub  = 'unmasked renderer blocked';
      conf = 'low';
    } else {
      gpu  = 'Not available';
      conf = 'none';
    }

    setCell('gpu', gpu, sub, conf);
  })();

  /* ── 8. HARDWARE ────────────────────────────────────────────────────── */
  (function() {
    const cores  = n.hardwareConcurrency || 0;
    const memGB  = n.deviceMemory;         // may be undefined
    let value = '', sub = '', conf = 'low';

    if (cores > 0 && memGB != null) {
      value = cores + ' cores';
      sub   = memGB + ' GB RAM (bucket)';
      conf  = 'medium'; // deviceMemory is quantised to 0.25,0.5,1,2,4,8 — not exact
    } else if (cores > 0) {
      value = cores + ' logical cores';
      sub   = 'RAM not exposed';
      conf  = 'medium';
    } else {
      value = 'Not exposed';
      conf  = 'none';
    }

    // Check RFP clamping (Firefox): if cores=2 and FF detected, call it out
    const ffLikely = typeof n.buildID !== 'undefined' && n.buildID;
    if (ffLikely && cores === 2) { sub += ' (possibly clamped by RFP)'; conf = 'low'; }

    setCell('hw', value, sub, conf);
  })();

  /* ── 9. LOCALE / TIMEZONE ───────────────────────────────────────────── */
  (function() {
    const tz  = Intl.DateTimeFormat().resolvedOptions().timeZone || '?';
    const loc = n.language || '?';
    const offset = -(new Date().getTimezoneOffset());
    const sign   = offset >= 0 ? '+' : '';
    const offStr = 'UTC' + sign + Math.floor(offset/60) + ':' + String(Math.abs(offset%60)).padStart(2,'0');

    // High confidence — JS always exposes these; only RFP can spoof them
    const rfpTZ = (tz === 'UTC' || tz === 'Etc/UTC') && typeof n.buildID !== 'undefined' && n.buildID;
    setCell('locale', loc, tz + ' · ' + offStr, rfpTZ ? 'low' : 'high');
  })();

  /* ── 10. PRIVACY MODE ───────────────────────────────────────────────── */
  (function() {
    let mode = '?', sub = '', conf = 'low';

    // Signals suggesting privacy tooling
    let signals = 0;

    // Canvas noise (detected earlier)
    const rfpCanvas = (function() {
      const c = document.createElement('canvas');
      c.width = 20; c.height = 1;
      const ctx = c.getContext('2d');
      ctx.fillStyle = '#FF0000';
      ctx.fillRect(0, 0, 1, 1);
      const px = ctx.getImageData(0, 0, 1, 1).data;
      return px[0] !== 255 || px[1] !== 0 || px[2] !== 0;
    })();
    if (rfpCanvas) signals++;

    // FF RFP screen
    if (screen.width === 1366 && screen.height === 768) signals++;

    // doNotTrack
    if (n.doNotTrack === '1') signals++;

    // globalPrivacyControl
    if (n.globalPrivacyControl) signals++;

    // navigator.webdriver (automation/bot)
    if (n.webdriver) { mode = 'Automated / Bot'; conf = 'high'; sub = 'webdriver=true'; }
    else if (signals >= 3) { mode = 'High Privacy';  conf = 'high';   sub = signals + ' RFP signals'; }
    else if (signals === 2) { mode = 'Privacy Tools'; conf = 'medium'; sub = signals + ' signals'; }
    else if (signals === 1) { mode = 'Some Privacy';  conf = 'low';    sub = '1 signal (DNT/GPC?)'; }
    else { mode = 'Standard';  conf = 'high';   sub = 'no RFP signals'; }

    setCell('privacy', mode, sub, conf);
  })();
}

/* ═══════════════════════════════════════════════════════════════════════════
   MASTER HASH & STATUS
═══════════════════════════════════════════════════════════════════════════ */
function computeMasterHash() {
  const parts = [
    FP.userAgent    || '',
    FP.platform     || '',
    FP.canvas       || '',
    FP.webglRender  || '',
    FP.gpuRenderer  || '',
    FP.audio        || '',
    FP.fonts        || '',
    FP.timezone     || '',
    FP.locale       || '',
    FP.screen       || '',
    FP.mathHash     || '',
    FP.featHash     || '',
    FP.hw_concurrency || '',
    FP.device_memory  || '',
    FP.uaCH         || '',
    FP.voices       || '',
    FP.remoteAddr   || '',
    PHP_DATA.remote_addr || '',
    FP.webkit   || '',
    FP.edge     || '',
    FP.firefox  || '',
  ];
  document.getElementById('master-hash').textContent = masterHash(parts);
  computeSummaryBar();

  // Entropy estimate: count unique non-empty signals
  const filled = parts.filter(p => p.length > 0).length;
  const entropy = Math.round(filled * 2.8);
  document.getElementById('entropy-score').innerHTML =
    `<span class="status-chip info">~${entropy} bits entropy · ${filled}/${parts.length} signals</span>`;

  addStatusChip('⬡ UA-CH: ' + (FP.uaCH ? 'full' : 'basic'), FP.uaCH ? 'ok' : 'warn');
  addStatusChip('🎨 Canvas: ' + (FP.canvas ? '✓' : '✗'), FP.canvas ? 'ok' : 'err');
  addStatusChip('🎮 WebGL: ' + (FP.gpuRenderer ? FP.gpuRenderer.split('/')[0].substring(0,20) : 'masked'), FP.gpuRenderer ? 'ok' : 'warn');
  addStatusChip('🔊 Audio: ' + (FP.audio ? '✓' : '✗'), FP.audio ? 'ok' : 'err');
}

/* ═══════════════════════════════════════════════════════════════════════════
   MAIN ORCHESTRATION
═══════════════════════════════════════════════════════════════════════════ */
async function main() {
  await collectIdentity();
  collectHeaders();
  collectScreen();
  collectCanvas();
  collectWebGL();
  await collectAudio();
  collectFonts();
  collectLocale();
  collectNetwork();
  await collectBattery();
  collectStorage();
  await collectMedia();
  collectSpeech();
  await collectPermissions();
  collectWebRTC();
  collectCSS();
  collectFeatures();
  collectMath();
  collectPerf();
  collectInput();
  await collectWebKit();
  await collectEdge();
  await collectFirefox();
  renderPHPRaw();

  setProgress(99, 'Computing master fingerprint...');
  computeMasterHash();
  setProgress(100, 'Done.');

  // Dismiss loader
  setTimeout(() => {
    const loader = document.getElementById('loader');
    loader.classList.add('done');
    setTimeout(() => loader.remove(), 500);
  }, 300);
}

// Fire
window.addEventListener('DOMContentLoaded', () => {
  // Restore saved theme (using documentElement for iOS Safari compat)
  try {
    if (localStorage.getItem('bp-theme') === 'light') {
      document.documentElement.classList.add('light');
      const icon  = document.getElementById('theme-icon');
      const label = document.getElementById('theme-label');
      if (icon)  icon.textContent  = '🌙';
      if (label) label.textContent = 'dark';
    }
  } catch(e) {}
  main();
});
</script>

</body>
</html>
