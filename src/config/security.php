<?php
$sessionGrants = false; //false = GJP check is done every time; true = GJP check is done once per hour; significantly improves performance, slightly descreases security (an attacker behind the same IP/NAT can impersonate a logged-in account for an hour, and a stolen GJP stays valid for an hour past a password change)
$unregisteredSubmissions = false; //false = green accounts can't upload levels, appear on the leaderboards etc; true = green accounts can do everything
$preactivateAccounts = true; //false = acounts need to be activated at tools/account/activateAccount.php; true = accounts can log in immediately

/*
	Captcha settings
	Currently the only supported provider is hCaptcha
	https://www.hcaptcha.com/
*/
$enableCaptcha = false;
$hCaptchaKey = "";
$hCaptchaSecret = "";

/*
	Hardening settings
*/
$botSecret = ""; //shared secret required by tools/bot/* endpoints (?token=...). If empty, bot endpoints are blocked entirely. Set a long random value and pass it from your bot.

$maxPage = 1000; //maximum page number accepted in paginated searches (page 1000 = offset 10000)
$maxLevelLength = 512000; //maximum accepted level data length in characters (uploadGJLevel.php)
$maxSongsPerSearch = 200; //maximum levelIDs accepted in an IN() clause built from client input (getGJLevels.php type 10)

$allowedTargetServers = array("www.boomlings.com", "boomlings.com"); //hosts allowed as linkAcc.php/levelToGD.php target servers (SSRF protection)

$maxStatValues = array( //hard caps for stats accepted by updateGJUserScore.php; values far above anything reachable by legit play
	"stars" => 1000000,
	"demons" => 100000,
	"coins" => 100000,
	"userCoins" => 100000,
	"diamonds" => 100000,
	"moons" => 100000
);

/*
	DDoS / DoS protection settings
	Per-IP request rate limiting runs in src/incl/lib/connection.php on every request,
	before the database is touched. Storage is file-based (src/data/ratelimit/), no DB
	writes. Clients that exceed a limit get HTTP 429 + Retry-After + body -1; IPs in the
	manual blocklist get HTTP 403.
*/
$enableRateLimit = true; // false = disable all per-IP rate limiting (not recommended)

// global per-IP sliding-window limit: at most $max requests per $window seconds, then blocked for $block seconds
$rateLimitGlobal = array('window' => 60, 'max' => 500, 'block' => 60);

// per-endpoint per-IP limits (keyed by script basename); same window/max/block semantics.
// per-endpoint limits apply on top of the global limit.
$rateLimitEndpoints = array(
	'getGJLevels.php'          => array('window' => 60, 'max' => 30,  'block' => 60),
	'getGJMapPacks.php'        => array('window' => 60, 'max' => 30,  'block' => 60),
	'getGJCreators.php'        => array('window' => 60, 'max' => 30,  'block' => 60),
	'getGJScores.php'          => array('window' => 60, 'max' => 60,  'block' => 60),
	'getGJComments.php'        => array('window' => 60, 'max' => 60,  'block' => 60),
	'downloadGJLevel.php'      => array('window' => 60, 'max' => 120, 'block' => 60),
	'uploadGJLevel.php'        => array('window' => 60, 'max' => 15,  'block' => 120),
	'uploadGJComment.php'      => array('window' => 60, 'max' => 60,  'block' => 60),
	'deleteGJComment.php'      => array('window' => 60, 'max' => 60,  'block' => 60),
	'deleteGJLevelUser.php'    => array('window' => 60, 'max' => 60,  'block' => 60),
	'likeGJItem.php'           => array('window' => 60, 'max' => 60,  'block' => 60),
	'rateGJLevel.php'          => array('window' => 60, 'max' => 30,  'block' => 60),
	'rateGJStars.php'          => array('window' => 60, 'max' => 30,  'block' => 60),
	'reportGJLevel.php'        => array('window' => 60, 'max' => 15,  'block' => 120),
	'updateGJUserScore.php'    => array('window' => 60, 'max' => 30,  'block' => 120),
	'accountManagement.php'    => array('window' => 60, 'max' => 30,  'block' => 300) // login/save flow
);

// manual blocklist file: one IP or CIDR per line, '#' starts a comment
$rateLimitBlockedIPsFile = __DIR__ . "/../data/blocked_ips.txt";

// maximum accepted HTTP request body size in bytes, enforced in connection.php via Content-Length
// (0 = disabled). Tune for your level/cloud-save sizes; see php.ini post_max_size in the README.
$maxRequestBody = 10485760; // 10 MB

$rateLimitPruneChance = 0.01; // probability (0-1) per request that stale rate-limit files are cleaned up

$blockFreeProxies = true; // true = check if person uses free proxy
$blockCommonVPNs = true; // true = check if person uses a common VPN
// URLs for IPs of proxies
$proxies['http'] = 'https://fhgdps.com/proxies/http.txt';
$proxies['https'] = 'https://fhgdps.com/proxies/https.txt';
$proxies['socks4'] = 'https://fhgdps.com/proxies/socks4.txt';
$proxies['socks5'] = 'https://fhgdps.com/proxies/socks5.txt';
$proxies['unknown'] = 'https://fhgdps.com/proxies/unknown.txt';
// URLs for IP ranges of VPNs (CIDR ranges; covers free and paid providers)
$vpns['vpn'] = 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt';
$vpns['datacenter'] = 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt'; // datacenter/hosting IPs - catches paid VPNs and proxies
