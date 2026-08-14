<?php
$sessionGrants = true; //false = GJP check is done every time; true = GJP check is done once per hour; significantly improves performance, slightly descreases security
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
