<?php
/*
	Per-IP request rate limiting + manual IP blocklist (DoS/DDoS protection).

	Runs from connection.php on every HTTP request, before the database is touched,
	so a flood of requests never reaches MySQL. Uses one small file per (IP, bucket)
	in src/data/ratelimit/ (no DB writes). Deliberately fail-open: if the storage
	directory is not writable, requests are allowed through and the error is logged.

	When a limit is exceeded the client gets HTTP 429 (with Retry-After) and body -1,
	which the Geometry Dash client treats as a failed request.
*/

require_once __DIR__ . "/blockProxyVPN.php";

if (!function_exists("rateLimit_isBlockedIP")) {
	// manual blocklist: one IP or CIDR per line, '#' starts a comment
	function rateLimit_isBlockedIP($ip, $listFile) {
		if (!is_file($listFile)) return false;
		$content = @file_get_contents($listFile);
		if ($content === false) return false;
		foreach (preg_split('/\r?\n/', $content) as $line) {
			$line = trim($line);
			if ($line === "" || $line[0] === '#') continue;
			if (strpos($line, '/') !== false || strpos($line, '-') !== false || strpos($line, '*') !== false) {
				if (ipInRange::ipv4_in_range($ip, $line)) return true;
			} elseif ($line === $ip) {
				return true;
			}
		}
		return false;
	}
}

if (!function_exists("rateLimit_check")) {
	// sliding-window counter persisted in $file.
	// returns array('ok' => bool, 'retryAfter' => seconds until the client may retry)
	function rateLimit_check($file, $window, $max, $block, $now = null) {
		if ($now === null) $now = time();
		$dir = dirname($file);
		if (!is_dir($dir)) @mkdir($dir, 0755, true);
		$fp = @fopen($file, 'c+');
		if (!$fp) return array('ok' => true, 'retryAfter' => 0); // fail open
		flock($fp, LOCK_EX);
		$size = filesize($file);
		$data = $size ? json_decode(fread($fp, $size), true) : null;
		if (!is_array($data)) $data = array('t' => array(), 'until' => 0);
		$until = (int)$data['until'];
		if ($until > $now) {
			flock($fp, LOCK_UN);
			fclose($fp);
			return array('ok' => false, 'retryAfter' => $until - $now);
		}
		// drop timestamps that fell out of the window
		$cutoff = $now - $window;
		$keep = array();
		foreach ((array)$data['t'] as $ts) {
			if ((int)$ts >= $cutoff) $keep[] = (int)$ts;
		}
		if (count($keep) >= $max) {
			$data = array('t' => $keep, 'until' => $now + $block);
			ftruncate($fp, 0);
			rewind($fp);
			fwrite($fp, json_encode($data));
			fflush($fp);
			flock($fp, LOCK_UN);
			fclose($fp);
			return array('ok' => false, 'retryAfter' => $block);
		}
		$keep[] = $now;
		$data = array('t' => $keep, 'until' => 0);
		ftruncate($fp, 0);
		rewind($fp);
		fwrite($fp, json_encode($data));
		fflush($fp);
		flock($fp, LOCK_UN);
		fclose($fp);
		return array('ok' => true, 'retryAfter' => 0);
	}
}

if (!function_exists("rateLimit_cleanup")) {
	// delete rate-limit files that haven't been touched in $maxAge seconds
	function rateLimit_cleanup($dir, $maxAge = 86400) {
		if (!is_dir($dir)) return;
		$now = time();
		foreach (glob($dir . "/*.dat") ?: array() as $f) {
			if (@filemtime($f) < $now - $maxAge) @unlink($f);
		}
	}
}

if (!function_exists("rateLimit_apply")) {
	// called from connection.php on every request; exits the request when blocked
	function rateLimit_apply() {
		require_once __DIR__ . "/../../config/security.php";
		if (empty($enableRateLimit)) return;

		$ip = blockProxyVPN_getIP();
		if ($ip === "" || !filter_var($ip, FILTER_VALIDATE_IP)) return; // CLI / non-IP remote

		$dir = __DIR__ . "/../../data/ratelimit/";
		if (!is_dir($dir)) @mkdir($dir, 0755, true);
		if (!is_writable($dir)) {
			error_log("[1.8-GDPS] ratelimit directory not writable, skipping rate limit");
			return; // fail open
		}

		// manual blocklist first (admin-maintained src/data/blocked_ips.txt)
		$blockedList = (isset($rateLimitBlockedIPsFile) && $rateLimitBlockedIPsFile !== "")
			? $rateLimitBlockedIPsFile : __DIR__ . "/../../data/blocked_ips.txt";
		if (rateLimit_isBlockedIP($ip, $blockedList)) {
			http_response_code(403);
			exit("-1");
		}

		$now = time();

		// global per-IP limit applies to every endpoint
		$g = array('window' => 60, 'max' => 500, 'block' => 60);
		if (!empty($rateLimitGlobal) && is_array($rateLimitGlobal)) $g = array_merge($g, $rateLimitGlobal);
		$result = rateLimit_check($dir . md5($ip . "|global") . ".dat", (int)$g['window'], (int)$g['max'], (int)$g['block'], $now);
		if (!$result['ok']) {
			http_response_code(429);
			header("Retry-After: " . $result['retryAfter']);
			exit("-1");
		}

		// per-endpoint per-IP limit for the hot API endpoints
		$script = basename($_SERVER['SCRIPT_NAME'] ?? $_SERVER['PHP_SELF'] ?? "");
		if ($script !== "" && !empty($rateLimitEndpoints) && isset($rateLimitEndpoints[$script])) {
			$e = $rateLimitEndpoints[$script];
			$result = rateLimit_check($dir . md5($ip . "|" . $script) . ".dat", (int)$e['window'], (int)$e['max'], (int)$e['block'], $now);
			if (!$result['ok']) {
				http_response_code(429);
				header("Retry-After: " . $result['retryAfter']);
				exit("-1");
			}
		}

		// occasional cleanup of stale buckets so the directory never grows unbounded
		if (!empty($rateLimitPruneChance) && mt_rand(1, 100) <= (int)($rateLimitPruneChance * 100)) {
			rateLimit_cleanup($dir);
		}
	}
}
?>
