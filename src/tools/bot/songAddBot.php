<?php
//error_reporting(0);
include "../../incl/lib/connection.php";
require_once "../../incl/lib/botCheck.php";
$link = $_GET["link"];
$name = $_GET["name"];
$author = $_GET["author"];
//echo "$name:$author:$link";
$urlparts = parse_url($link);
$scheme = strtolower($urlparts["scheme"] ?? "");
if($scheme != "http" AND $scheme != "https") exit("-2");
$ch = curl_init($link);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
curl_setopt($ch, CURLOPT_HEADER, TRUE);
curl_setopt($ch, CURLOPT_NOBODY, TRUE);
curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
$data = curl_exec($ch);
$size = curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
curl_close($ch);
$size = round($size / 1024 / 1024, 2);
$hash = "";
$name = str_replace("#", "", $name);
$name = str_replace(":", "", $name);
$name = str_replace("~", "", $name);
$name = str_replace("|", "", $name);
$query = $db->prepare("SELECT count(*) FROM songs WHERE download = :download");
$query->execute([':download' => $link]);
$count = $query->fetchColumn();
if($count != 0){
	echo "This song already exists in our database.";
}else{
	$query = $db->prepare("INSERT INTO songs (name, authorID, authorName, size, download, hash) 
										VALUES (:name, '9', :author, :size, :download, :hash)");
	$query->execute([':name' => $name, ':download' => $link, ':author' => $author, ':size' => $size, ':hash' => $hash]);
	echo $db->lastInsertId();
}
?>