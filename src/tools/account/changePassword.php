<?php
include "../../incl/lib/connection.php";
include_once "../../config/security.php";
require "../../incl/lib/generatePass.php";
require_once "../../incl/lib/exploitPatch.php";
include_once "../../incl/lib/defuse-crypto.phar";
use Defuse\Crypto\KeyProtectedByPassword;
use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
$userName = ExploitPatch::remove($_POST["userName"] ?? "");
$oldpass = $_POST["oldpassword"] ?? "";
$newpass = $_POST["newpassword"] ?? "";
$salt = "";
if($userName != "" AND $newpass != "" AND $oldpass != ""){
$pass = GeneratePass::isValidUsrname($userName, $oldpass);
if ($pass == 1) {
	//creating pass hash
	$passhash = password_hash($newpass, PASSWORD_DEFAULT);
	$query = $db->prepare("SELECT accountID FROM accounts WHERE userName=:userName");
	$query->execute([':userName' => $userName]);
	$accountID = $query->fetchColumn();
	if (!$accountID) {
		exit("Invalid old password or nonexistent account. <a href='changePassword.php'>Try again</a>");
	}
	$query = $db->prepare("UPDATE accounts SET password=:password, salt=:salt WHERE userName=:userName");	
	$query->execute([':password' => $passhash, ':userName' => $userName, ':salt' => $salt]);
	// re-hash GJP2 so the new password can be used to log in from the game client
	GeneratePass::assignGJP2($accountID, $newpass);
	echo "Password changed. <a href='..'>Go back to tools</a>";
	//decrypting save
	$saveFile = "../../data/accounts/$accountID";
	$keyFile = "../../data/accounts/keys/$accountID";
	if(file_exists($saveFile) AND file_exists($keyFile)){
		$saveData = file_get_contents($saveFile);
		$protected_key_encoded = file_get_contents($keyFile);
		if($protected_key_encoded != ""){
			$protected_key = KeyProtectedByPassword::loadFromAsciiSafeString($protected_key_encoded);
			$user_key = $protected_key->unlockKey($oldpass);
			try {
				$saveData = Crypto::decrypt($saveData, $user_key);
			} catch (Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException $ex) {
				exit("Unable to update save data encryption");	
			}
			file_put_contents($saveFile,$saveData);
			file_put_contents($keyFile,"");
		}
	}
}else{
	echo "Invalid old password or nonexistent account. <a href='changePassword.php'>Try again</a>";

}
}else{
	echo '<form action="changePassword.php" method="post">Username: <input type="text" name="userName"><br>Old password: <input type="password" name="oldpassword"><br>New password: <input type="password" name="newpassword"><br><input type="submit" value="Change"></form>';
}
?>