'use strict';

/*
 * BrowserPrint v4.0+ audit compatibility layer (enhanced post-release).
 *
 * Builds on v4.0's auditedMain:
 * - Ensures ALL collectors are properly awaited before hash/export/loader finalization.
 * - Adds unhandledrejection safety.
 *
 * v4.0+ enhancements prepared here (recommended code changes):
 * - Dynamically updates the UI version span to v4.0 (and notes "audited").
 * - Adds a secure context status chip/warning if page is not served over HTTPS
 *   (many probes like UA-CH, enumerateDevices, clipboard, WebRTC require it).
 * - Safer global main override with existence check.
 * - Provides a shared detectCanvasNoise() helper (extracted from duplicate logic
 *   in WebKit and privacy sections) for future DRY improvements or direct use.
 * - Minor: groups engine probes last as before; ensures computeMasterHash awaits.
 *
 * This file is injected via index.php (or can be loaded manually after app.js).
 * It overrides the main orchestrator defined in browserprint.app.js.
 */

(function() {
  // Shared helper extracted for DRY (addresses previous duplicate canvas noise test)
  window.detectCanvasNoise = function detectCanvasNoise() {
    try {
      const c = document.createElement('canvas');
      c.width = 20; c.height = 1;
      const ctx = c.getContext('2d');
      ctx.fillStyle = '#FF0000';
      ctx.fillRect(0, 0, 1, 1);
      const px = ctx.getImageData(0, 0, 1, 1).data;
      return px[0] !== 255 || px[1] !== 0 || px[2] !== 0;
    } catch (e) {
      return false;
    }
  };

  // Safer override of main
  if (typeof main === 'function' || typeof main === 'undefined') {
    main = async function auditedMain() {
      await runStep('identity', collectIdentity);

      await Promise.all([
        runStep('headers', collectHeaders),
        runStep('screen', collectScreen),
        runStep('canvas', collectCanvas),
        runStep('webgl', collectWebGL),
        runStep('audio', collectAudio),
        runStep('battery', collectBattery),
        runStep('media', collectMedia),
        runStep('permissions', collectPermissions),
      ]);

      await Promise.all([
        runStep('fonts', collectFonts),
        runStep('locale', collectLocale),
        runStep('network', collectNetwork),
        runStep('storage', collectStorage),
        runStep('speech', collectSpeech),
        runStep('webrtc', collectWebRTC),
        runStep('css', collectCSS),
        runStep('features', collectFeatures),
        runStep('math', collectMath),
        runStep('perf', collectPerf),
        runStep('input', collectInput),
      ]);

      await Promise.all([
        runStep('webkit', collectWebKit),
        runStep('edge', collectEdge),
        runStep('firefox', collectFirefox),
        runStep('phpRaw', renderPHPRaw),
      ]);

      setProgress(99, 'Computing master fingerprint...');
      await runStep('masterHash', computeMasterHash);
      setProgress(100, 'Done.');

      // v4.0+ post-hash enhancement: update version display and add secure context warning
      try {
        const verSpan = document.querySelector('#masthead h1 span.ver');
        if (verSpan) {
          verSpan.textContent = 'v4.0 // intranet only // solarian design (audited + enhanced)';
          verSpan.style.color = '#58d4f0';
        }

        // Add secure context status if not HTTPS/secure
        if (!window.isSecureContext) {
          const bar = document.getElementById('status-bar');
          if (bar) {
            const chip = document.createElement('span');
            chip.className = 'status-chip warn';
            chip.innerHTML = '⚠ Not secure context — some probes limited (UA-CH, media, clipboard, WebRTC)';
            bar.appendChild(chip);
          }
        }
      } catch (e) {
        console.warn('[BrowserPrint] Post-audit UI enhancement error:', e);
      }
    };
  }

  // Unhandled rejection safety (from v4.0)
  window.addEventListener('unhandledrejection', event => {
    console.error('[BrowserPrint] unhandled rejection:', event.reason);
    if (typeof dismissLoader === 'function') {
      dismissLoader();
    }
  });

  // Optional: expose for debugging
  window.BrowserPrintAuditVersion = '4.1-enhanced';
})();
