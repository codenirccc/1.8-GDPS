<?php
session_set_cookie_params(array('httponly' => true, 'secure' => !empty($_SERVER['HTTPS']), 'samesite' => 'Lax'));
session_start();
include "../lib/connection.php";
// yoinked from 99webTools
// random 6-character code drawn from an unambiguous alphabet (no 0/O, 1/I/L)
$characters = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
$code = "";
for ($i = 0; $i < 6; $i++) {
	$code .= $characters[random_int(0, strlen($characters) - 1)];
}
$_SESSION["code"] = $code;
$im = imagecreatetruecolor(70, 26);
$bg = imagecolorallocate($im, 0, 0, 0); // background color black
$fg = imagecolorallocate($im, 255, 255, 255); // text color white
imagefill($im, 0, 0, $bg);
// a few noise lines to make OCR harder
for ($i = 0; $i < 3; $i++) {
	$noise = imagecolorallocate($im, random_int(100, 255), random_int(100, 255), random_int(100, 255));
	imageline($im, random_int(0, 70), random_int(0, 26), random_int(0, 70), random_int(0, 26), $noise);
}
imagestring($im, 5, 5, 5, $code, $fg);
header("Cache-Control: no-cache, must-revalidate");
header('Content-type: image/png');
imagepng($im);
imagedestroy($im);
?>