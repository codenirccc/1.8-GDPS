<?php
session_set_cookie_params(array('httponly' => true, 'secure' => !empty($_SERVER['HTTPS']), 'samesite' => 'Lax'));
session_start();
if (isset($_POST["userName"]) AND isset($_POST["password"]) AND isset($_POST["captcha"])) {
	require "../../incl/lib/connection.php";
	require_once "../../incl/lib/generatePass.php";
	$gp = new generatePass();
	require_once "../../incl/lib/exploitPatch.php";
	$ep = new exploitPatch();
	$userName = $ep->remove($_POST["userName"]);
	$password = $_POST["password"];
	$captchaOk = ($_POST["captcha"] != "" AND strcasecmp(($_SESSION["code"] ?? ""), $_POST["captcha"]) === 0);
	unset($_SESSION["code"]);
	if (!$captchaOk) {
		echo "Captcha check failed. Please try again.";
	} else {
		$query = $db->prepare("SELECT accountID FROM accounts WHERE userName = :userName LIMIT 1");
		$query->execute([':userName' => $userName]);
		if ($query->rowCount() == 0) {
			// equalize timing with a dummy password check so account existence can't be inferred
			password_verify($password, '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi');
			echo "Incorrect username-password combination. Please try again.";
		} else {
			$accountID = $query->fetchColumn();
			if ($gp->isValid($accountID, $password)) {
				require_once "../../incl/lib/mainLib.php";
				$gs = new mainLib();
				$verificationKey = $gs->generateVerificationKey($accountID);
				if ($verificationKey) echo "New verification key generated: " . $verificationKey . "<br>Verification keys will only last for 15 minutes.<br><a href='index.php'>Go back to account management.</a><br><br>";
				else echo "Failed to generate a verification key! Please try again.";
			} else {
				echo "Incorrect username-password combination. Please try again.";
			}
		}
	}
	echo "<br><br>";
}
?>
<form action="generateKey.php" method="post">
	Username: <input type="text" name="userName" minlength=3 maxlength=15><br>
	Password: <input type="password" name="password" minlength=6 maxlength=20><br>
	Verify Captcha: <input name="captcha" type="text"><br>
	<img src="../../incl/misc/captchaGen.php"><br><br>
	<input type="submit" value="Generate">
</form>