<?php
/**
 * BrowserPrint — entry point.
 *
 * The entire application (PHP server-side collection, HTML, CSS, and
 * JavaScript) ships as a single monolithic file: fingerprint.php.
 * This alias simply hands the request to it, so both / and
 * /fingerprint.php serve the tool.
 */
require __DIR__ . '/fingerprint.php';
