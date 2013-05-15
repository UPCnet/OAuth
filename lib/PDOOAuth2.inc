<?php

/**
 * Sample OAuth2 Library PDO DB Implementation.
 */

// Values in config.php

require "config.php";

include "OAuth2.inc";

/**
 * OAuth2 Library PDO DB Implementation.
 */
class PDOOAuth2 extends OAuth2 {

  private $db;

  /**
   * Overrides OAuth2::__construct().
   */
  public function __construct() {
    parent::__construct();

    try {
      $this->db = new PDO(PDO_DSN, PDO_USER, PDO_PASS);
    } catch (PDOException $e) {
      die('Connection failed: ' . $e->getMessage());
    }
  }

  /**
   * Release DB connection during destruct.
   */
  function __destruct() {
    $this->db = NULL; // Release db connection
  }

  /**
   * Handle PDO exceptional cases.
   */
  private function handleException($e) {
    echo "Database error: " . $e->getMessage();
    exit;
  }

  /**
   * Encryption helper function
   */
  private function encrypt_token($oauth_token, $keysecret = NULL) {
     if (!is_null($keysecret))
       return (base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($keysecret), $oauth_token, MCRYPT_MODE_CBC, md5(md5($keysecret)))));
     else
       return (base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5(KEYSECRET), $oauth_token, MCRYPT_MODE_CBC, md5(md5(KEYSECRET)))));
  }

  /**
   * Decryption helper function
   */
  private function decrypt_token($oauth_token, $keysecret = NULL) {
     if (!is_null($keysecret))
       return rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($keysecret), base64_decode($oauth_token), MCRYPT_MODE_CBC, md5(md5($keysecret))), "\0"); 
     else
       return rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5(KEYSECRET), base64_decode($oauth_token), MCRYPT_MODE_CBC, md5(md5(KEYSECRET))), "\0");
  }

  /**
   * Little helper function to add a new client to the database.
   *
   * Do NOT use this in production! This sample code stores the secret
   * in plaintext!
   *
   * @param $client_id
   *   Client identifier to be stored.
   * @param $client_secret
   *   Client secret to be stored.
   * @param $redirect_uri
   *   Redirect URI to be stored.
   */
  public function addClient($client_id, $client_secret, $redirect_uri) {
    try {
      $sql = "INSERT INTO clients (client_id, client_secret, redirect_uri) VALUES (:client_id, :client_secret, :redirect_uri)";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
      $stmt->bindParam(":client_secret", $client_secret, PDO::PARAM_STR);
      $stmt->bindParam(":redirect_uri", $redirect_uri, PDO::PARAM_STR);
      $stmt->execute();
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::checkClientCredentials().
   *
   * Do NOT use this in production! This sample code stores the secret
   * in plaintext!
   */
  protected function checkClientCredentials($client_id, $client_secret = NULL) {
    try {
      $sql = "SELECT client_secret FROM clients WHERE client_id = :client_id";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetch(PDO::FETCH_ASSOC);

      if ($client_secret === NULL)
          return $result !== FALSE;

      return $result["client_secret"] == $client_secret;
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::getRedirectUri().
   */
  protected function getRedirectUri($client_id) {
    try {
      $sql = "SELECT redirect_uri FROM clients WHERE client_id = :client_id";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetch(PDO::FETCH_ASSOC);

      if ($result === FALSE)
          return FALSE;

      return isset($result["redirect_uri"]) && $result["redirect_uri"] ? $result["redirect_uri"] : NULL;
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::getIssuedAccessToken().
   */
  protected function getIssuedAccessToken($user_id = NULL, $scope = NULL, $client_id) {
    try {
      $sql = "SELECT oauth_token FROM tokens 
		WHERE user_id = :user_id and scope = :scope and client_id = :client_id 
		and (noexpiry = true or expires > ".time()." ) order by expires desc limit 1";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":user_id", strtolower($user_id), PDO::PARAM_STR);
      $stmt->bindParam(":scope", $scope, PDO::PARAM_STR);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetch(PDO::FETCH_ASSOC);

      if ($result !== FALSE)
        return $this->decrypt_token($result["oauth_token"],strtolower($user_id));
      else
        return NULL;
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::getAccessToken().
   */
  protected function getAccessToken($oauth_token, $user_id = NULL ) {
  // DB - Anadimos parametro noexpiry para posibilitar tokens de vida ilimitada
    try {
      $encrypted = $this->encrypt_token($oauth_token,strtolower($user_id));

      $sql = "SELECT client_id, expires, scope, noexpiry, user_id FROM tokens WHERE oauth_token = :oauth_token";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":oauth_token", $encrypted, PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetch(PDO::FETCH_ASSOC);

      return $result !== FALSE ? $result : NULL;
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::getUserTokenListFromBBDD().
   */
  protected function getUserTokenListFromBBDD($user_id) {
    try {
	// No mostramos tokens expirados o revocados
      $sql = "SELECT client_id, expires-3600 as creation, scope, noexpiry 
		FROM tokens 
		WHERE user_id = :user_id and ( noexpiry = true or expires > ".time()." ) order by expires desc";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":user_id", strtolower($user_id), PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

      return $result !== FALSE ? $result : NULL;
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }


  /**
   * Implements OAuth2::setTokenRevoked().
   */

  protected function setTokenRevoked($oauth_token, $user_id = NULL) {
    try {
      $encrypted = $this->encrypt_token($oauth_token,strtolower($user_id));

      $sql = "UPDATE tokens SET noexpiry=NULL, expires=0 WHERE oauth_token = :oauth_token";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":oauth_token", $encrypted, PDO::PARAM_STR);
      $stmt->execute();

      $sql = "SELECT expires,noexpiry FROM tokens WHERE oauth_token = :oauth_token";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":oauth_token", $encrypted, PDO::PARAM_STR);
      $stmt->execute();
      $result = $stmt->fetch(PDO::FETCH_ASSOC);
      
      return $result !== FALSE ? $result : NULL;

    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Implements OAuth2::setAccessToken().
   */
  protected function setAccessToken($oauth_token, $client_id, $expires, $scope = NULL, $user_id = NULL) {
    try {
      $encrypted = $this->encrypt_token($oauth_token,strtolower($user_id));
   
      $sql = "INSERT INTO tokens (oauth_token, client_id, expires, scope, user_id, noexpiry) VALUES (:oauth_token, :client_id, :expires, :scope, :user_id, TRUE)";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":oauth_token", $encrypted, PDO::PARAM_STR);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
      $stmt->bindParam(":expires", $expires, PDO::PARAM_INT);
      $stmt->bindParam(":scope", $scope, PDO::PARAM_STR);
      $stmt->bindParam(":user_id", strtolower($user_id), PDO::PARAM_STR);

      $stmt->execute();
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Overrides OAuth2::getSupportedGrantTypes().
   */
  protected function getSupportedGrantTypes() {
    return array(
      OAUTH2_GRANT_TYPE_AUTH_CODE,
      OAUTH2_GRANT_TYPE_USER_CREDENTIALS,
      OAUTH2_GRANT_TYPE_ALUMNI_USER_CREDENTIALS,
    );
  }

  /**
   * Overrides OAuth2::getSupportedScopes().
   */
  protected function getSupportedScopes() {
    return array(
        'iphonecli',
        'androidcli',
        'webcli',
        'desktopcli',
        'widgetcli',
    );
  }
  /**
   * Overrides OAuth2::getSupportedAuthResponseTypes().
   */
  protected function getSupportedAuthResponseTypes() {
    return array(
      OAUTH2_AUTH_RESPONSE_TYPE_AUTH_CODE,
      OAUTH2_AUTH_RESPONSE_TYPE_ACCESS_TOKEN,
      OAUTH2_AUTH_RESPONSE_TYPE_CODE_AND_TOKEN
    );
  }


  /**
   * Overrides OAuth2::getAuthCode().
   */
  protected function getAuthCode($code) {
    try {
      $sql = "SELECT code, client_id, redirect_uri, expires, scope FROM auth_codes WHERE code = :code";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":code", $code, PDO::PARAM_STR);
      $stmt->execute();

      $result = $stmt->fetch(PDO::FETCH_ASSOC);

      return $result !== FALSE ? $result : NULL;
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Overrides OAuth2::setAuthCode().
   */
  protected function setAuthCode($code, $client_id, $redirect_uri, $expires, $scope = NULL) {
    try {
      $sql = "INSERT INTO auth_codes (code, client_id, redirect_uri, expires, scope) VALUES (:code, :client_id, :redirect_uri, :expires, :scope)";
      $stmt = $this->db->prepare($sql);
      $stmt->bindParam(":code", $code, PDO::PARAM_STR);
      $stmt->bindParam(":client_id", $client_id, PDO::PARAM_STR);
      $stmt->bindParam(":redirect_uri", $redirect_uri, PDO::PARAM_STR);
      $stmt->bindParam(":expires", $expires, PDO::PARAM_INT);
      $stmt->bindParam(":scope", $scope, PDO::PARAM_STR);
      $stmt->execute();
    } catch (PDOException $e) {
      $this->handleException($e);
    }
  }

  /**
   * Overrides OAuth2::checkUserCredentials().
   */

  protected function checkUserCredentials($client_id, $username, $password) {
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
    }
  }


  /**
   * Overrides OAuth2::checkAlumniUserCredentials().
   */

  protected function checkAlumniUserCredentials($username, $password) {
    try {        
        $dbh = new PDO(ALUMNI_PDO_DSN, ALUMNI_PDO_USER, ALUMNI_PDO_PASS);
        $dbh->setAttribute(PDO::ATTR_TIMEOUT,10);
        $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        /*** prepare the select statement ***/
        $stmt = $dbh->prepare("SELECT nip FROM dades_persona WHERE adreca_electronica like :param_username AND contrasenya like :param_password
                                  AND login_blocat like 'N'");

        /*** bind the parameters ***/
        $stmt->bindParam(':param_username', strtolower($username), PDO::PARAM_STR);
        $stmt->bindParam(':param_password', sha1($password), PDO::PARAM_STR);

        /*** execute the prepared statement ***/
        $stmt->execute();

        /*** check for a result ***/
        $user_id = $stmt->fetchColumn();

      /*** close the database connection ***/
      $dbh = null;

        /*** if we have no result then fail boat ***/
        if($user_id == false)
          return false;

      /*** all was fine, user validated ***/
      return true;
    }
    catch(PDOException $e) {
      $dbh = null;
      die('Connection failed: ' . $e->getMessage());
    }
  }
 
}
