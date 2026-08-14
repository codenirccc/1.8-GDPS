<?php
// Authentication check for tools/bot/* endpoints
// Requires a secret shared token (?token=...). If $botSecret is empty in config/security.php, bot access is blocked entirely.
require_once __DIR__ . "/../../config/security.php";
if(empty($botSecret) OR !isset($_GET["token"]) OR !hash_equals($botSecret, $_GET["token"])) {
	http_response_code(403);
	exit("-1");
}
?>