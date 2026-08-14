<?php
chdir(dirname(__FILE__));
include "../lib/connection.php";
require_once "../lib/exploitPatch.php";
require_once "../lib/mainLib.php";
$gs = new mainLib();

if(!isset($_POST['itemID']))
	exit(-1);

$type = isset($_POST['type']) ? $_POST['type'] : 1;
if(!is_numeric($type) OR $type < 1 OR $type > 4)
	exit("-1");
$itemID = ExploitPatch::remove($_POST['itemID']);
$isLike = isset($_POST['like']) ? $_POST['like'] : 1;
$ip = $gs->getIP();

// likebot prevention: a like/dislike only counts if the request comes from a linked account.
// either an accountID + GJP/GJP2 (newer clients) or a udid that is linked to an account (1.8 clients)
require_once "../lib/GJPCheck.php";
$accountID = 0;
if (!empty($_POST['accountID'])) {
	$accountID = ExploitPatch::remove($_POST['accountID']);
	if (!empty($_POST['gjp'])) {
		GJPCheck::validateGJPOrDie($_POST['gjp'], $accountID);
	} elseif (!empty($_POST['gjp2'])) {
		GJPCheck::validateGJP2OrDie($_POST['gjp2'], $accountID);
	} else {
		exit("-1");
	}
}
if (!$accountID) {
	$accountID = $gs->getLegacyAccountID();
	if (!$accountID) exit("-1");
}

$query = $db->prepare("SELECT count(*) FROM actions_likes WHERE itemID=:itemID AND type=:type AND ip=INET6_ATON(:ip)");
$query->execute([':type' => $type, ':itemID' => $itemID, ':ip' => $ip]);
if($query->fetchColumn() > 2)
	exit("-1");

$query = $db->prepare("INSERT INTO actions_likes (itemID, type, isLike, ip) VALUES (:itemID, :type, :isLike, INET6_ATON(:ip))");
$query->execute([':itemID' => $itemID, ':type' => $type, ':isLike' => $isLike, ':ip' => $ip]);

switch($type){
	case 1:
		$table = "levels";
		$column = "levelID";
		break;
	case 2:
		$table = "comments";
		$column = "commentID";
		break;
	case 3:
		$table = "acccomments";
		$column = "commentID";
		break;
	case 4:
		$table = "lists";
		$column = "listID";
		break;
}

$query=$db->prepare("SELECT likes FROM $table WHERE $column = :itemID LIMIT 1");
$query->execute([':itemID' => $itemID]);
$likes = $query->fetchColumn();
if($isLike == 1)
	$sign = "+";
else
	$sign = "-";

$query=$db->prepare("UPDATE $table SET likes = likes $sign 1 WHERE $column = :itemID");
$query->execute([':itemID' => $itemID]);
echo "1";
?>