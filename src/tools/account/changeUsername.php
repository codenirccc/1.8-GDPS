<?php
include "../../incl/lib/connection.php";
require "../../incl/lib/generatePass.php";
require_once "../../incl/lib/exploitPatch.php";
//here im getting all the data
$userName = ExploitPatch::remove($_POST["userName"] ?? "");
$newusr = $_POST["newusr"] ?? "";
$password = $_POST["password"] ?? "";
if($userName != "" AND $newusr != "" AND $password != ""){
	$pass = GeneratePass::isValidUsrname($userName, $password);
	if ($pass == 1) {
		if(strlen($newusr) < 3 OR strlen($newusr) > 20)
			exit("Username must be between 3 and 20 characters. <a href='changeUsername.php'>Try again</a>");
		if(!preg_match('/^[A-Za-z0-9 _\-\.]+$/', $newusr))
			exit("Invalid characters in the new username. <a href='changeUsername.php'>Try again</a>");
		$query = $db->prepare("SELECT COUNT(*) FROM accounts WHERE userName = :newusr");
		$query->execute([':newusr' => $newusr]);
		if($query->fetchColumn() != 0)
			exit("That username is already taken. <a href='changeUsername.php'>Try again</a>");
		$query = $db->prepare("UPDATE accounts SET userName=:newusr WHERE userName=:userName");	
		$query->execute([':newusr' => $newusr, ':userName' => $userName]);
		if($query->rowCount()==0){
			echo "Invalid password or nonexistant account. <a href='changeUsername.php'>Try again</a>";
		}else{
			echo "Username changed. <a href='..'>Go back to tools</a>";
		}
	}else{
		echo "Invalid password or nonexistant account. <a href='changeUsername.php'>Try again</a>";
	}
}else{
	echo '<form action="changeUsername.php" method="post">Old username: <input type="text" name="userName"><br>New username: <input type="text" name="newusr"><br>Password: <input type="password" name="password"><br><input type="submit" value="Change"></form>';
}
?>