'use strict';

/*
 * BrowserPrint audit compatibility layer.
 *
 * The original orchestrator starts a number of collectors without awaiting
 * their promises. That allows the fingerprint, export data, and loader state
 * to be finalized before WebRTC and other probes have completed. Because the
 * DOMContentLoaded callback resolves `main` when it fires, replacing the
 * global function here (before DOMContentLoaded) corrects the behavior without
 * duplicating the collector implementation.
 */

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
};

// Promise rejections do not trigger the window "error" event in every browser.
// Mirror the existing last-resort loader release for rejected promises.
window.addEventListener('unhandledrejection', event => {
  console.error('[BrowserPrint] unhandled rejection:', event.reason);
  dismissLoader();
});
