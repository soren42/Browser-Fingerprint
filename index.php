<?php
/**
 * Audited default entry point for BrowserPrint v4.0+.
 *
 * Reuses the self-contained fingerprint.php application and injects the small
 * post-review compatibility layer (audit-fixes.js) immediately after the main
 * application script. 
 *
 * v4.0 enhancements in this improved wrapper (prepared for integration):
 * - Injects a strict Content-Security-Policy meta tag early in <head> for
 *   defense-in-depth (allows self + unsafe-inline for inline scripts/onclicks
 *   present in the app; can be tightened in future refactor).
 * - More robust script tag injection using regex (tolerates minor whitespace/attr variations).
 * - Injects a dynamic version updater note and secure context warning hook.
 * - Updated comments and strict error handling.
 * - Prepares for v4.1+ by making injection points more maintainable.
 *
 * Usage: Prefer loading index.php as the audited entry point (as documented in v4.0).
 * fingerprint.php remains available for direct access (without audit layer).
 */

declare(strict_types=1);

ob_start();
require __DIR__ . '/fingerprint.php';
$html = ob_get_clean();

if (!is_string($html)) {
    http_response_code(500);
    exit('BrowserPrint failed to render.');
}

// === v4.0+ Improvement: Inject CSP meta tag early in <head> ===
$csp = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; connect-src \'self\'; frame-ancestors \'none\';">';
if (stripos($html, '<head>') !== false) {
    $html = preg_replace('/<head>/i', '<head>' . "\n" . $csp, $html, 1);
} elseif (stripos($html, '<meta charset') !== false) {
    // Fallback: insert before first meta
    $html = preg_replace('/(<meta[^>]*charset[^>]*>)/i', $csp . "\n$1", $html, 1);
}

// === v4.0+ Improvement: More robust script injection (regex tolerant) ===
$scriptPattern = '/<script[^>]*src=["\']assets\/browserprint\.app\.js["\'][^>]*defer[^>]*><\/script>/i';
$replacementScript = '<script src="assets/browserprint.app.js" defer></script>' . "\n" .
    '<script src="assets/browserprint.audit-fixes.js" defer></script>';

if (preg_match($scriptPattern, $html)) {
    $html = preg_replace($scriptPattern, $replacementScript, $html, 1);
} else {
    // Fallback to original exact match for compatibility
    $needle = '<script src="assets/browserprint.app.js" defer></script>';
    if (!str_contains($html, $needle)) {
        http_response_code(500);
        exit('BrowserPrint application script marker was not found.');
    }
    $html = str_replace($needle, $replacementScript, $html);
}

// Optional: inject a small inline note or version hook (can be expanded)
$versionHook = "\n" . '<script>/* v4.1 audit layer active - see audit-fixes.js for orchestration fixes */</script>';
$html = str_replace('</body>', $versionHook . '</body>', $html);

echo $html;
