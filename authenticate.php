<?php
function authenticate($user, $password) {
    // Active Directory server
    $ldap_host = "ldaps://ldap-pre.upc.edu";
    $ldap_base = "ou=users,dc=upc,dc=edu";
 
    // connect to active directory
    $ldapconn = ldap_connect($ldap_host);
    ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
 
    // verify user and password
    if($bind = @ldap_bind($ldapconn, "cn=".$user.",".$ldap_base , $password)) {
        // valid
        $access = true;
        ldap_unbind($ldapconn);
 
        if ($access != 0) {
            // establish session variables
            $_SESSION['client_id'] = $user;
            return true;
        } else {
            // user has no rights
            return false;
        }
 
    } else {
        // invalid name or password
        return false;
    }
}
?>
