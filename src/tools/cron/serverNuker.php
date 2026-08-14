<hr>
<?php
// EMERGENCY SERVER NUKER - panic kill switch for raids.
// Wipes the entire database (schema, all tables, accounts, levels, songs, everything)
// and deletes all stored level/account/cache files, leaving the server empty.
// SAFETY: disabled by default. Enable by setting $nukeSecret in src/config/security.php,
// optionally restrict to $nukeAllowedIPs. Trigger: serverNuker.php?key=<secret>&confirm=1
include "../../incl/lib/connection.php";
require_once "../../config/security.php";
require_once "../../incl/lib/blockProxyVPN.php";

if (empty($nukeSecret)) {
	echo "Nuker disabled (set \$nukeSecret in src/config/security.php).";
	exit;
}

$ip = blockProxyVPN_getIP();
if (!empty($nukeAllowedIPs) && !in_array($ip, $nukeAllowedIPs)) {
	echo "Not authorized.";
	exit;
}

if (!isset($_GET["key"]) || !is_string($_GET["key"]) || !hash_equals($nukeSecret, $_GET["key"])) {
	echo "Invalid key.";
	exit;
}

if (!isset($_GET["confirm"]) || $_GET["confirm"] !== "1") {
	echo "Confirmation required (confirm=1).";
	exit;
}

echo "Starting server wipe<br>";
ob_flush();
flush();

// drop the entire database (all tables, schema, accounts, levels) and re-create it empty.
// connecting without a database name so DROP DATABASE is allowed.
$nukeDb = new PDO("mysql:host=$servername;port=$port;charset=utf8mb4", $username, $password, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
$nukeDb->exec("DROP DATABASE IF EXISTS `" . $dbname . "`");
echo "Database dropped<br>";
ob_flush();
flush();
$nukeDb->exec("CREATE DATABASE `" . $dbname . "` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci");
echo "Database recreated empty<br>";
ob_flush();
flush();
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
	echo "Wiped " . $dir . "<br>";
	ob_flush();
	flush();
}

echo "<hr>Server wiped - re-import database.sql to restore the schema.<hr>";
?>
<hr>
