<?php

/**
 * @file
 * Sample token endpoint.
 *
 * Obviously not production-ready code, just simple and to the point.
 *
 * In reality, you'd probably use a nifty framework to handle most of the crud for you.
 */

//WARNING: ONLY FOS PRE-AUTHENTICATED USAGE 
require "lib/PDOOAuth2b.inc";
#Delay
#sleep(15);

# Debug a fitxer
/* 
$file="/tmp/oauth.log";
$handle=fopen($file,'w');
ob_start();
var_dump($_POST);
$data = ob_get_clean();
fwrite($handle,$data);
fclose($handle);
*/

$oauth = new PDOOAuth2b();
$oauth->grantAccessToken();

?>
