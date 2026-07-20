<?php
/**
 * Audited default entry point.
 *
 * Reuses the self-contained fingerprint.php application and injects the small
 * post-review compatibility layer immediately after the main application
 * script. This avoids maintaining a second copy of the HTML/PHP shell.
 */

declare(strict_types=1);

ob_start();
require __DIR__ . '/fingerprint.php';
$html = ob_get_clean();

if (!is_string($html)) {
    http_response_code(500);
    exit('BrowserPrint failed to render.');
}

$needle = '<script src="assets/browserprint.app.js" defer></script>';
$replacement = $needle . "\n" .
    '<script src="assets/browserprint.audit-fixes.js" defer></script>';

if (!str_contains($html, $needle)) {
    http_response_code(500);
    exit('BrowserPrint application script marker was not found.');
}

echo str_replace($needle, $replacement, $html);
