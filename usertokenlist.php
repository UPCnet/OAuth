<?php

require "lib/PDOOAuth2.inc";

$oauth = new PDOOAuth2();
$oauth->getUserTokenList();

?>
