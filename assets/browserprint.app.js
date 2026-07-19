/* ═══════════════════════════════════════════════════════════════════════════
   §22  WEBKIT / SAFARI / APPLE PLATFORM
   Covers Safari (macOS), MobileSafari (iOS/iPadOS), and WebKit-based apps.
   Tests fall into three tiers:
     A) Definitive — only present in WebKit/JavaScriptCore
     B) Strong indicator — heavily WebKit-weighted but occasionally elsewhere
     C) Derived — parsed from UA / capability inference
═══════════════════════════════════════════════════════════════════════════ */
async function collectWebKit() {
  setProgress(95, 'Running WebKit/Safari/Apple probes...');
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
  setProgress(96, 'Running Edge/Chromium-specific probes...');
  const rows = [];
  const w   = window;
  const n   = navigator;
  const ua  = n.userAgent;
  const doc = document;

  /* ── UA string dissection (first, sets context for everything else) ──── */
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
  setProgress(97, 'Running Firefox/Gecko probes...');
  const rows = [];
  const w   = window;
  const n   = navigator;
  const ua  = n.userAgent;
  const doc = document;

  /* ── UA string dissection ─────────────────────────────────────────────── */
  const isFirefox      = /Firefox\//.test(ua);
  const isGecko        = /Gecko\//.test(ua) && !/like Gecko/.test(ua.split('Gecko/')[1] || '');
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
  rows.push(['UA: Tor Browser pattern (FF + rv:)', yesno(isFirefox && !!geckoVerMatch), (isFirefox && geckoVerMatch) ? 'yellow' : 'dim']);
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
      const androidM = ua.match(/Android ([\d.]+)/i);
      if (androidM) {
        os = 'Android';
        ver = ver || androidM[1].split('.').slice(0,2).join('.');
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
    let gamut = 'sRGB';
    if (window.matchMedia('(color-gamut:rec2020)').matches)      gamut = 'Rec.2020';
    else if (window.matchMedia('(color-gamut:p3)').matches)        gamut = 'P3 wide';

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
   COPY HASH & EXPORT REPORT
═══════════════════════════════════════════════════════════════════════════ */
function copyHash() {
  const text = document.getElementById('master-hash').textContent;
  const done = ok => addStatusChip(ok ? '⧉ Hash copied to clipboard' : '⧉ Copy failed', ok ? 'ok' : 'err');
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => done(true), () => done(false));
  } else {
    // Fallback for non-secure contexts (plain-HTTP intranet)
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
      done(true);
    } catch (e) { done(false); }
  }
}

function exportReport() {
  // Harvest every rendered section row from the DOM into structured JSON.
  const sections = {};
  document.querySelectorAll('.section').forEach(sec => {
    const title = (sec.querySelector('.section-header .title') || {}).textContent || sec.id;
    const rows = [];
    sec.querySelectorAll('.section-body .row').forEach(r => {
      const k = r.querySelector('.row-key');
      const v = r.querySelector('.row-val');
      if (k && v) rows.push([k.textContent.trim(), v.textContent.trim()]);
    });
    sections[title] = rows;
  });

  const report = {
    tool:           'BrowserPrint',
    version:        '3.8',
    generatedUtc:   new Date().toISOString(),
    masterHash:     FP.stableHash  || null,
    sessionHash:    FP.sessionHash || null,
    rawSignals:     FP,
    serverSide:     PHP_DATA,
    sections:       sections,
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'browserprint-' + (FP.stableHash || 'report') + '.json';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  addStatusChip('⇓ Report exported', 'ok');
}

/* ═══════════════════════════════════════════════════════════════════════════
   MASTER HASH & STATUS
═══════════════════════════════════════════════════════════════════════════ */
function computeMasterHash() {
  // STABLE signals — identical across visits from the same device/browser,
  // regardless of network. This is the actual "device fingerprint".
  const stableParts = [
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
    FP.webkit   || '',
    FP.edge     || '',
    FP.firefox  || '',
  ];
  // VOLATILE signals — change between sessions (network, voice-load race,
  // battery state). Hashed separately; never mix into the device hash.
  const sessionParts = stableParts.concat([
    FP.remoteAddr || '',
    PHP_DATA.remote_addr || '',
    FP.forwardedFor || '',
    FP.voices   || '',
    FP.battery  || '',
    FP.rtcIPs   || '',
  ]);
  FP.stableHash  = masterHash(stableParts);
  FP.sessionHash = masterHash(sessionParts);
  document.getElementById('master-hash').textContent = FP.stableHash;
  const sessEl = document.getElementById('session-hash');
  if (sessEl) sessEl.textContent = FP.sessionHash;
  computeSummaryBar();

  // Entropy estimate: count unique non-empty stable signals
  const filled = stableParts.filter(p => p.length > 0).length;
  const entropy = Math.round(filled * 2.8);
  document.getElementById('entropy-score').innerHTML =
    `<span class="status-chip info">~${entropy} bits entropy · ${filled}/${stableParts.length} stable signals</span>`;

  addStatusChip('⬡ UA-CH: ' + (FP.uaCH ? 'full' : 'basic'), FP.uaCH ? 'ok' : 'warn');
  addStatusChip('🎨 Canvas: ' + (FP.canvas ? '✓' : '✗'), FP.canvas ? 'ok' : 'err');
  addStatusChip('🎮 WebGL: ' + (FP.gpuRenderer ? FP.gpuRenderer.split('/')[0].substring(0,20) : 'masked'), FP.gpuRenderer ? 'ok' : 'warn');
  addStatusChip('🔊 Audio: ' + (FP.audio ? '✓' : '✗'), FP.audio ? 'ok' : 'err');
}

/* ═══════════════════════════════════════════════════════════════════════════
   MAIN ORCHESTRATION
═══════════════════════════════════════════════════════════════════════════ */
// Run one collector with full error isolation: a failing probe must never
// abort the scan or strand the loading screen.
async function runStep(name, fn) {
  try {
    await fn();
  } catch (e) {
    console.error('[BrowserPrint] collector failed:', name, e);
    addStatusChip('⚠ ' + name + ': ' + (e && e.message ? e.message : 'error'), 'err');
  }
}

async function main() {
  // Identity first — later stages read FP.uaCH.
  await runStep('identity', collectIdentity);

  // Independent async collectors run in parallel (was fully sequential).
  runStep('headers', collectHeaders);
  runStep('screen', collectScreen);
  runStep('canvas', collectCanvas);
  runStep('webgl', collectWebGL);
  await Promise.all([
    runStep('audio', collectAudio),
    runStep('battery', collectBattery),
    runStep('media', collectMedia),
    runStep('permissions', collectPermissions),
  ]);

  runStep('fonts', collectFonts);
  runStep('locale', collectLocale);
  runStep('network', collectNetwork);
  runStep('storage', collectStorage);
  await runStep('speech', collectSpeech);   // waits (bounded) for voices
  runStep('webrtc', collectWebRTC);
  runStep('css', collectCSS);
  runStep('features', collectFeatures);
  runStep('math', collectMath);
  runStep('perf', collectPerf);
  runStep('input', collectInput);
  await runStep('webkit', collectWebKit);
  await runStep('edge', collectEdge);
  await runStep('firefox', collectFirefox);
  runStep('phpRaw', renderPHPRaw);

  setProgress(99, 'Computing master fingerprint...');
  runStep('masterHash', computeMasterHash);
  setProgress(100, 'Done.');
}

function dismissLoader() {
  const loader = document.getElementById('loader');
  if (!loader) return;
  loader.classList.add('done');
  setTimeout(() => loader.remove(), 500);
}

// Last-resort: any uncaught error still releases the loading screen.
window.addEventListener('error', dismissLoader);

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
  main().catch(e => console.error('[BrowserPrint] main() failed:', e))
        .finally(() => setTimeout(dismissLoader, 300));
});
