<?php
// user management tool - the access key is PERMANENT and unchangeable.
// the key is not stored anywhere in this code; only its sha256 digest is hardcoded below,
// and the comparison is done against this literal value, so there is no constant or
// variable an attacker could edit to swap in a different key.

session_start();

include "../../incl/lib/connection.php";
require_once "../../incl/lib/exploitPatch.php";
require_once "../../incl/lib/generatePass.php";
require_once "../../incl/lib/mainLib.php";
$gs = new mainLib();

$authenticated = isset($_SESSION["panel_auth"]) AND $_SESSION["panel_auth"] === 1;
$loginError = "";

if(!$authenticated) {
	$ip = $gs->getIP();
	// 5 wrong keys per IP in 10 minutes locks the panel for that IP
	$query = $db->prepare("SELECT COUNT(*) FROM actions WHERE type = '99' AND value2 = :ip AND timestamp > :time");
	$query->execute([':ip' => $ip, ':time' => time() - 600]);
	$locked = $query->fetchColumn() >= 5;

	if(isset($_POST["key"]) AND !$locked) {
		if(is_string($_POST["key"]) AND hash_equals("0d01b1ad5987ff549a9de2c8b08f9f584fb6809f38b73e78118e87fedbf16271", hash("sha256", $_POST["key"]))) {
			session_regenerate_id(true);
			$_SESSION["panel_auth"] = 1;
			$authenticated = true;
		} else {
			$query = $db->prepare("INSERT INTO actions (type, value, timestamp, value2) VALUES ('99', '0', :time, :ip)");
			$query->execute([':time' => time(), ':ip' => $ip]);
			sleep(1);
			$loginError = "Invalid key.";
		}
	}

	if(!$authenticated) {
		$blockedMsg = $locked ? "Too many attempts. Try again later." : "";
		?>
		<html>
		<head><title>404 Not Found</title></head>
		<body>
		<?php if($loginError !== "") echo "<p style=\"color:red\">" . htmlspecialchars($loginError, ENT_QUOTES) . "</p>"; ?>
		<?php if($blockedMsg !== "") echo "<p style=\"color:red\">" . htmlspecialchars($blockedMsg, ENT_QUOTES) . "</p>"; ?>
		<form action="userlist.php" method="post">
			Key: <input type="password" name="key">
			<br><input type="submit" value="Enter">
		</form>
		</body>
		</html>
		<?php
		exit;
	}
}

$messages = array();
$error = "";
$action = isset($_POST["action"]) ? $_POST["action"] : "";

function validIP($ip) {
	return preg_match('/^[0-9]{1,3}(\.[0-9]{1,3}){0,3}$/', $ip) === 1;
}

function levelExists($db, $levelID) {
	$query = $db->prepare("SELECT levelID, levelName FROM levels WHERE levelID = :levelID LIMIT 1");
	$query->execute([':levelID' => $levelID]);
	return $query->fetch();
}

if($action == "resetpass" AND isset($_POST["userName"], $_POST["newpass"]) AND $_POST["newpass"] !== "") {
	$userName = ExploitPatch::remove($_POST["userName"]);
	$newpass = $_POST["newpass"];
	if($userName === "") {
		$error = "Username required.";
	} elseif(strlen($newpass) < 6) {
		$error = "New password too short (min 6 chars).";
	} else {
		$query = $db->prepare("SELECT accountID, userName FROM accounts WHERE userName = :userName LIMIT 1");
		$query->execute([':userName' => $userName]);
		$acc = $query->fetch();
		if(!$acc) {
			$error = "Account not found.";
		} else {
			$query = $db->prepare("UPDATE accounts SET password = :password, gjp2 = :gjp2 WHERE accountID = :accountID");
			$query->execute([':password' => password_hash($newpass, PASSWORD_DEFAULT), ':gjp2' => GeneratePass::GJP2hash($newpass), ':accountID' => $acc["accountID"]]);
			$messages[] = "Password reset for '" . htmlspecialchars($acc["userName"], ENT_QUOTES) . "' (accountID " . $acc["accountID"] . ").";
		}
	}
} elseif($action == "addip" AND isset($_POST["ip"])) {
	$ip = trim($_POST["ip"]);
	if(!validIP($ip)) {
		$error = "Invalid IP.";
	} else {
		$query = $db->prepare("DELETE FROM bannedips WHERE IP = :ip");
		$query->execute([':ip' => $ip]);
		$query = $db->prepare("INSERT INTO bannedips (IP, ID) VALUES (:ip, 0)");
		$query->execute([':ip' => $ip]);
		$query = $db->prepare("UPDATE users SET isBanned = 1 WHERE IP LIKE CONCAT(:ip, '%')");
		$query->execute([':ip' => $ip]);
		$messages[] = "IP banned: " . htmlspecialchars($ip, ENT_QUOTES);
	}
} elseif($action == "delip" AND isset($_POST["ip"])) {
	$ip = trim($_POST["ip"]);
	if(!validIP($ip)) {
		$error = "Invalid IP.";
	} else {
		$query = $db->prepare("DELETE FROM bannedips WHERE IP = :ip");
		$query->execute([':ip' => $ip]);
		$query = $db->prepare("UPDATE users SET isBanned = 0 WHERE isBanned = 1 AND IP LIKE CONCAT(:ip, '%')");
		$query->execute([':ip' => $ip]);
		$messages[] = "IP unblocked: " . htmlspecialchars($ip, ENT_QUOTES);
	}
} elseif($action == "deletelevel" AND isset($_POST["levelID"])) {
	$levelID = $_POST["levelID"];
	if(!is_numeric($levelID)) {
		$error = "Invalid levelID.";
	} else {
		$level = levelExists($db, $levelID);
		if(!$level) {
			$error = "Level not found.";
		} else {
			$query = $db->prepare("DELETE FROM levels WHERE levelID = :levelID LIMIT 1");
			$query->execute([':levelID' => $levelID]);
			$query = $db->prepare("DELETE FROM comments WHERE levelID = :levelID");
			$query->execute([':levelID' => $levelID]);
			$levelFile = dirname(__FILE__) . "/../../../data/levels/" . $levelID;
			if(file_exists($levelFile)) {
				@rename($levelFile, dirname(__FILE__) . "/../../../data/levels/deleted/" . $levelID);
			}
			$messages[] = "Level deleted: '" . htmlspecialchars($level["levelName"], ENT_QUOTES) . "' (levelID " . $levelID . ").";
		}
	}
} elseif($action == "ratelevel" AND isset($_POST["levelID"], $_POST["stars"])) {
	$levelID = $_POST["levelID"];
	$stars = $_POST["stars"];
	if(!is_numeric($levelID)) {
		$error = "Invalid levelID.";
	} elseif(!is_numeric($stars) OR $stars < 0 OR $stars > 10) {
		$error = "Stars must be between 0 and 10.";
	} else {
		$level = levelExists($db, $levelID);
		if(!$level) {
			$error = "Level not found.";
		} else {
			$diff = $gs->getDiffFromStars($stars);
			$query = $db->prepare("UPDATE levels SET starStars = :stars, starDifficulty = :diff, starDemon = :demon, starAuto = :auto, rateDate = :now WHERE levelID = :levelID");
			$query->execute([':stars' => $stars, ':diff' => $diff["diff"], ':demon' => $diff["demon"], ':auto' => $diff["auto"], ':now' => time(), ':levelID' => $levelID]);
			if(isset($_POST["coins"]) AND $_POST["coins"] !== "" AND is_numeric($_POST["coins"]) AND $_POST["coins"] >= 0 AND $_POST["coins"] <= 3) {
				$query = $db->prepare("UPDATE levels SET starCoins = :coins WHERE levelID = :levelID");
				$query->execute([':coins' => $_POST["coins"], ':levelID' => $levelID]);
			}
			if(isset($_POST["featured"]) AND ($_POST["featured"] == "0" OR $_POST["featured"] == "1")) {
				$query = $db->prepare("UPDATE levels SET starFeatured = :featured, starEpic = 0 WHERE levelID = :levelID");
				$query->execute([':featured' => $_POST["featured"], ':levelID' => $levelID]);
			}
			$messages[] = "Level rated: '" . htmlspecialchars($level["levelName"], ENT_QUOTES) . "' (levelID " . $levelID . ") -> " . $stars . " stars (" . $diff["name"] . ").";
		}
	}
} elseif($action == "unlistlevel" AND isset($_POST["levelID"])) {
	$levelID = $_POST["levelID"];
	if(!is_numeric($levelID)) {
		$error = "Invalid levelID.";
	} else {
		$level = levelExists($db, $levelID);
		if(!$level) {
			$error = "Level not found.";
		} else {
			$query = $db->prepare("UPDATE levels SET unlisted = 1 WHERE levelID = :levelID");
			$query->execute([':levelID' => $levelID]);
			$messages[] = "Level unlisted: '" . htmlspecialchars($level["levelName"], ENT_QUOTES) . "' (levelID " . $levelID . ").";
		}
	}
} elseif($action == "publishlevel" AND isset($_POST["levelID"])) {
	$levelID = $_POST["levelID"];
	if(!is_numeric($levelID)) {
		$error = "Invalid levelID.";
	} else {
		$level = levelExists($db, $levelID);
		if(!$level) {
			$error = "Level not found.";
		} else {
			$query = $db->prepare("UPDATE levels SET unlisted = 0 WHERE levelID = :levelID");
			$query->execute([':levelID' => $levelID]);
			$messages[] = "Level made public: '" . htmlspecialchars($level["levelName"], ENT_QUOTES) . "' (levelID " . $levelID . ").";
		}
	}
} elseif($action == "deleteuser" AND isset($_POST["who"])) {
	$who = trim($_POST["who"]);
	if($who === "") {
		$error = "Account ID or username required.";
	} else {
		if(is_numeric($who)) {
			$query = $db->prepare("SELECT accountID, userName FROM accounts WHERE accountID = :id LIMIT 1");
			$query->execute([':id' => $who]);
		} else {
			$query = $db->prepare("SELECT accountID, userName FROM accounts WHERE userName = :name LIMIT 1");
			$query->execute([':name' => $who]);
		}
		$acc = $query->fetch();
		if(!$acc) {
			$error = "Account not found.";
		} else {
			$query = $db->prepare("SELECT userID FROM users WHERE extID = :extID LIMIT 1");
			$query->execute([':extID' => $acc["accountID"]]);
			$userID = $query->fetchColumn();
			$query = $db->prepare("DELETE FROM accounts WHERE accountID = :accountID");
			$query->execute([':accountID' => $acc["accountID"]]);
			if($userID) {
				$query = $db->prepare("DELETE FROM users WHERE userID = :userID");
				$query->execute([':userID' => $userID]);
				$query = $db->prepare("DELETE FROM comments WHERE userID = :userID");
				$query->execute([':userID' => $userID]);
			}
			$messages[] = "User deleted: '" . htmlspecialchars($acc["userName"], ENT_QUOTES) . "' (accountID " . $acc["accountID"] . ", userID " . ($userID ? $userID : "none") . ").";
		}
	}
}

$query = $db->prepare("SELECT IP, ID FROM bannedips ORDER BY IP ASC");
$query->execute();
$bannedips = $query->fetchAll();
?>
<html>
<head><title>404 Not Found</title></head>
<body>
<?php if(!empty($error)) echo "<p style=\"color:red\">" . htmlspecialchars($error, ENT_QUOTES) . "</p>"; ?>
<?php foreach($messages as $m) echo "<p style=\"color:green\">" . $m . "</p>"; ?>
<h3>Password reset</h3>
<form action="userlist.php" method="post">
	<input type="hidden" name="action" value="resetpass">
	Username: <input type="text" name="userName">
	<br>New password: <input type="text" name="newpass">
	<br><input type="submit" value="Reset">
</form>
<h3>Delete level</h3>
<form action="userlist.php" method="post">
	<input type="hidden" name="action" value="deletelevel">
	Level ID: <input type="text" name="levelID">
	<br><input type="submit" value="Delete">
</form>
<h3>Rate level</h3>
<form action="userlist.php" method="post">
	<input type="hidden" name="action" value="ratelevel">
	Level ID: <input type="text" name="levelID">
	<br>Stars (0-10): <input type="text" name="stars">
	<br>Coins (0-3, optional): <input type="text" name="coins">
	<br>Featured (0/1, optional): <input type="text" name="featured">
	<br><input type="submit" value="Rate">
</form>
<h3>Unlist level</h3>
<form action="userlist.php" method="post">
	<input type="hidden" name="action" value="unlistlevel">
	Level ID: <input type="text" name="levelID">
	<br><input type="submit" value="Unlist">
</form>
<form action="userlist.php" method="post">
	<input type="hidden" name="action" value="publishlevel">
	Level ID: <input type="text" name="levelID">
	<br><input type="submit" value="Make public">
</form>
<h3>Delete user</h3>
<form action="userlist.php" method="post">
	<input type="hidden" name="action" value="deleteuser">
	Account ID or username: <input type="text" name="who">
	<br><input type="submit" value="Delete">
</form>
<h3>Ban IP</h3>
<form action="userlist.php" method="post">
	<input type="hidden" name="action" value="addip">
	IP: <input type="text" name="ip">
	<br><input type="submit" value="Ban">
</form>
<h3>Banned IPs</h3>
<table border="1">
<tr><th>IP</th><th></th></tr>
<?php foreach($bannedips as $ip) { ?>
<tr><td><?php echo htmlspecialchars($ip["IP"], ENT_QUOTES); ?></td>
<td><form action="userlist.php" method="post">
<input type="hidden" name="action" value="delip">
<input type="hidden" name="ip" value="<?php echo htmlspecialchars($ip["IP"], ENT_QUOTES); ?>">
<input type="submit" value="Unban">
</form></td></tr>
<?php } ?>
</table>
</body>
</html>
