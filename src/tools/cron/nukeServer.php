<?php
// EMERGENCY SERVER NUKER - panic kill switch for raids.
// The link key is not stored in plaintext: it is AES-256-CBC encrypted below and decrypted
// with the hardcoded AES-256 key at runtime. No dependency on src/config/security.php.
// Trigger: nukeServer.php?key=<link key>  ->  HTML page  ->  confirm  ->  wipe
include "../../config/connection.php";

define("NUKE_AES_KEY", hex2bin("ff0aa7f1395be7d575a391c65810ebfce7300a6441a809861e9a570ba161a4ab"));
define("NUKE_CIPHER", "4FqlWCd4ORwBU7A0F6t4FGvb5OO8N3Y9ba9NsLHCpQOIusN+S2ZwnxQrVsMgzWFM2nQA97jKJg755q1ju1ooTTTRFC/AqvSz+DyZ6lPACyQ=");
define("NUKE_IV", "R6Ay7JyjG2eJQYiLbbE/KA==");

// recover the link key
$nukeKey = @openssl_decrypt(base64_decode(NUKE_CIPHER), "aes-256-cbc", NUKE_AES_KEY, OPENSSL_RAW_DATA, base64_decode(NUKE_IV));
if (!$nukeKey) {
	http_response_code(404);
	echo "haha noice try";
	exit;
}

if (!isset($_GET["key"]) || !is_string($_GET["key"]) || !hash_equals($nukeKey, $_GET["key"])) {
	http_response_code(404);
	echo "haha noice try";
	exit;
}

if (isset($_GET["confirm"]) && $_GET["confirm"] === "1") {
	// wipe the entire database (all tables, schema, accounts, levels) and re-create it empty
	$nukeDb = new PDO("mysql:host=$servername;port=$port;charset=utf8mb4", $username, $password, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
	$nukeDb->exec("DROP DATABASE IF EXISTS `" . $dbname . "`");
	$nukeDb->exec("CREATE DATABASE `" . $dbname . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci");
	$nukeDb = null;

	// delete stored level files, account keys and cached proxy/vpn lists
	$wipeDirs = array(
		dirname(__FILE__) . "/../../data/levels/",
		dirname(__FILE__) . "/../../data/accounts/",
		dirname(__FILE__) . "/../../data/proxycache/"
	);
	foreach ($wipeDirs as $dir) {
		if (!is_dir($dir)) continue;
		$files = glob($dir . "*");
		if ($files === false) continue;
		foreach ($files as $file) {
			if (is_dir($file)) {
				foreach (glob($file . "/*") as $inner) {
					if (is_file($inner)) @unlink($inner);
				}
			} else {
				@unlink($file);
			}
		}
	}
	header("Content-Type: text/html; charset=utf-8");
	echo "<html><body style=\"background:#111;color:#ff4444;font-family:monospace\"><h1>DONE</h1><p>Database dropped and recreated empty. Level files wiped. Re-import database.sql to restore the schema.</p></body></html>";
	exit;
}
?>
<!DOCTYPE html>
<html>
<head>
	<title>404 Not Found</title>
	<style>
		body { background:#111; color:#eee; font-family:monospace; text-align:center; padding-top:60px; }
		.box { display:inline-block; border:1px solid #ff4444; padding:40px; border-radius:8px; }
		h1 { color:#ff4444; letter-spacing:4px; }
		button { background:#ff4444; color:#fff; border:0; padding:16px 40px; font-size:18px; cursor:pointer; border-radius:6px; margin-top:20px; }
		button:hover { background:#ff6666; }
	</style>
</head>
<body>
	<div class="box">
		<h1>NUKE</h1>
		<p>Emergency server wipe. This destroys the whole database and all levels.</p>
		<form method="get">
			<input type="hidden" name="key" value="<?php echo htmlspecialchars($nukeKey, ENT_QUOTES); ?>">
			<label><input type="checkbox" name="confirm" value="1" required> I understand, wipe everything</label><br>
			<button type="submit">INITIATE</button>
		</form>
	</div>
</body>
</html>
