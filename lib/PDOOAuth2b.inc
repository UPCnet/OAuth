<?php

/**
 * Sample OAuth2 Library PDO DB Implementation.
 * Nomes cridable des del cas-token!!! Fake validacio..
 */

// Values in config.php

#require "config.php";

include "PDOOAuth2.inc";

/**
 * OAuth2 Library PDO DB Implementation.
 */
class PDOOAuth2b extends PDOOAuth2 {

  /**
   * Overrides PDOOAuth2::checkUserCredentials().
   */

  protected function checkUserCredentials($client_id, $username, $password = NULL) {

    //Do not check LDAP
    /*
    // connect to active directory
    $ldapconn = ldap_connect(LDAP_SERVER);
    ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);

    // verify user and password
    if($bind = @ldap_bind($ldapconn, "cn=".$username.",".LDAP_BASE , $password)) {
        // valid
        $access = true;
        ldap_unbind($ldapconn);

        if ($access != 0) {
            return true;
        } else {
            // user has no rights
            return false;
      }

    } else {
        // invalid name or password
        return false;
    }*/
     // To-DO : Alguna comprovacio? Pending..
     return true;
  }

 
}
