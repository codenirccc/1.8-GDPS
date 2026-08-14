<?php
require_once __DIR__ . "/ip_in_range.php";

if (!function_exists("blockProxyVPN_isCloudFlareIP")) {
	function blockProxyVPN_isCloudFlareIP($ip) {
		$cf_ips = array(
			'173.245.48.0/20',
			'103.21.244.0/22',
			'103.22.200.0/22',
			'103.31.4.0/22',
			'141.101.64.0/18',
			'108.162.192.0/18',
			'190.93.240.0/20',
			'188.114.96.0/20',
			'197.234.240.0/22',
			'198.41.128.0/17',
			'162.158.0.0/15',
			'104.16.0.0/13',
			'104.24.0.0/14',
			'172.64.0.0/13',
			'131.0.72.0/22'
		);
		foreach ($cf_ips as $cf_ip) {
			if (ipInRange::ipv4_in_range($ip, $cf_ip)) {
				return true;
			}
		}
		return false;
	}
}

if (!function_exists("blockProxyVPN_getIP")) {
	function blockProxyVPN_getIP() {
		if (!isset($_SERVER['REMOTE_ADDR'])) return "";
		if (isset($_SERVER['HTTP_CF_CONNECTING_IP']) && blockProxyVPN_isCloudFlareIP($_SERVER['REMOTE_ADDR']))
			return $_SERVER['HTTP_CF_CONNECTING_IP'];
		if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && ipInRange::ipv4_in_range($_SERVER['REMOTE_ADDR'], '127.0.0.0/8'))
			return trim(explode(",", $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
		return $_SERVER['REMOTE_ADDR'];
	}
}

if (!function_exists("blockProxyVPN_load")) {
	// downloads a list into the cache dir, refreshing it if older than $ttl seconds.
	// on download failure the stale cached copy is used, so a broken source never blocks everyone.
	function blockProxyVPN_load($url, $cacheFile, $ttl = 43200) {
		if (is_file($cacheFile) && filemtime($cacheFile) > time() - $ttl) {
			return file_get_contents($cacheFile);
		}
		$content = @file_get_contents($url, false, stream_context_create(array(
			'http' => array('timeout' => 15),
			'https' => array('timeout' => 15)
		)));
		if ($content !== false) {
			@file_put_contents($cacheFile, $content, LOCK_EX);
			return $content;
		}
		if (is_file($cacheFile)) {
			return file_get_contents($cacheFile);
		}
		return false;
	}
}

if (!function_exists("blockProxyVPN_hasIP")) {
	// exact IP match against a plain list (one IP per line)
	function blockProxyVPN_hasIP($content, $ip) {
		if ($content === false) return false;
		return preg_match('/(^|\n)' . preg_quote($ip, '/') . '(\r?\n|$)/', $content) === 1;
	}
}

if (!function_exists("blockProxyVPN_hasRange")) {
	// CIDR range match against a list (one CIDR per line).
	// ranges wider than /8 are checked directly; for /9 or narrower the first octet
	// must match, which skips ~99.6% of a large list without changing correctness.
	function blockProxyVPN_hasRange($content, $ip) {
		if ($content === false) return false;
		$ipFirst = (int)explode(".", $ip)[0];
		foreach (explode("\n", $content) as $line) {
			$line = trim($line);
			if ($line === "") continue;
			$slash = strpos($line, "/");
			if ($slash === false) {
				if ($line === $ip) return true;
				continue;
			}
			$prefix = (int)substr($line, $slash + 1);
			if ($prefix > 8) {
				$rangeFirst = (int)explode(".", $line)[0];
				if ($rangeFirst !== $ipFirst) continue;
			}
			if (ipInRange::ipv4_in_range($ip, $line)) return true;
		}
		return false;
	}
}

if (!function_exists("blockProxyVPN_check")) {
	// returns true if the given IP is a free proxy or a VPN/datacenter IP
	function blockProxyVPN_check($ip) {
		if ($ip === "" OR !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return false;
		require_once __DIR__ . "/../../config/security.php";
		if (empty($blockFreeProxies) && empty($blockCommonVPNs)) return false;

		$cacheDir = __DIR__ . "/../../data/proxycache/";
		if (!is_dir($cacheDir)) @mkdir($cacheDir, 0755, true);
		$resultDir = $cacheDir . "results/";
		if (!is_dir($resultDir)) @mkdir($resultDir, 0755, true);

		// per-IP result cache (10 minutes) so repeat requests don't re-scan the lists
		$resultFile = $resultDir . md5($ip);
		if (is_file($resultFile) && filemtime($resultFile) > time() - 600) {
			return trim(file_get_contents($resultFile)) === "1";
		}

		$blocked = false;
		if (!empty($blockFreeProxies) && !empty($proxies)) {
			foreach ($proxies as $name => $url) {
				$content = blockProxyVPN_load($url, $cacheDir . "proxy_" . $name . ".txt");
				if (blockProxyVPN_hasIP($content, $ip)) { $blocked = true; break; }
			}
		}
		if (!$blocked && !empty($blockCommonVPNs) && !empty($vpns)) {
			foreach ($vpns as $name => $url) {
				$content = blockProxyVPN_load($url, $cacheDir . "vpn_" . $name . ".txt");
				if (blockProxyVPN_hasRange($content, $ip)) { $blocked = true; break; }
			}
		}
		@file_put_contents($resultFile, $blocked ? "1" : "0", LOCK_EX);
		return $blocked;
	}
}
