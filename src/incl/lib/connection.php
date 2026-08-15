<?php
include dirname(__FILE__)."/../../config/connection.php";
require_once dirname(__FILE__)."/../../config/security.php";
@header('Content-Type: text/html; charset=utf-8');

// DoS/DDoS guards run exactly once per request, even though connection.php is
// re-included by many mainLib methods for every database access.
if (!isset($GLOBALS['requestGuardDone'])) {
	$GLOBALS['requestGuardDone'] = true;

	// oversized request bodies are rejected before anything else (DoS)
	if (isset($maxRequestBody) && $maxRequestBody > 0 && isset($_SERVER['CONTENT_LENGTH']) && (int)$_SERVER['CONTENT_LENGTH'] > $maxRequestBody) {
		http_response_code(413);
		exit("-1");
	}

	// per-IP rate limiting runs before the database is touched, so floods never reach MySQL
	require_once dirname(__FILE__) . "/ratelimit.php";
	rateLimit_apply();
}

if(!isset($port))
	$port = 3306;
    try {
        $db = new PDO("mysql:host=$servername;port=$port;dbname=$dbname;charset=utf8mb4", $username, $password, array(
        PDO::ATTR_PERSISTENT => true,
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_EMULATE_PREPARES => false
    ));
    // set the PDO error mode to exception
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }
    catch(PDOException $e)
    {
        error_log("[1.8-GDPS] Database connection failed: " . $e->getMessage());
        http_response_code(500);
        echo "Connection failed. Please try again later.";
        exit;
    }

    // proxy/vpn blocking - runs once per request. anonymous/local traffic is never blocked.
    if (!isset($GLOBALS['proxyCheckDone'])) {
        $GLOBALS['proxyCheckDone'] = true;
        require_once dirname(__FILE__) . "/blockProxyVPN.php";
        require_once dirname(__FILE__) . "/../../config/security.php";
        if (!empty($blockFreeProxies) || !empty($blockCommonVPNs)) {
            $clientIP = blockProxyVPN_getIP();
            if (blockProxyVPN_check($clientIP)) {
                http_response_code(403);
                echo "-1";
                exit;
            }
        }
    }
?>