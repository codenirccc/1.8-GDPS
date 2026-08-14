<?php
//error_reporting(0);
include "../../incl/lib/connection.php";
require_once "../../incl/lib/botCheck.php";
$page = isset($_GET["page"]) AND is_numeric($_GET["page"]) ? (int)$_GET["page"] : 0;
if($page > 0){
	$page = $page - 1;
}else{
	$page = 0;
}
if($page > 10000){
	$page = 10000;
}
$humanpage = $page +1;
$page = $page*20;
echo "***SHOWING PAGE $humanpage***\r\n";
$query = $db->prepare("SELECT ID,name FROM songs WHERE ID >= 5000000 ORDER BY ID DESC LIMIT $page , 20");
$query->execute();
$result = $query->fetchAll();
foreach($result as &$song){
	$name = str_replace("*", "", $song["name"]);
	$name = str_replace("_", " ", $song["name"]);
	echo "**".$song["ID"]." : **".$name."\r\n";
}
?>
***USE !songlist <page> TO SEE MORE SONGS***