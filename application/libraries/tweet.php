<?php
	
	class tweet {
		
		private $_oauth = NULL;
		
		function __construct()
		{
			$this->_oauth = new tweetOauth();
		}
		
		function __call($method, $args)
		{
			if ( method_exists($this, $method) )
			{
				return call_user_func_array(array($this, $method), $args);
			}
			
			return call_user_func_array(array($this->_oauth, $method), $args);
		}
		
		function logged_in()
		{
			return $this->_oauth->loggedIn();
		}
		function get_access_secret()
		{
			return $this->_oauth->getAccessSecret();
		}
		function set_callback($url)
		{
			$this->_oauth->setCallback($url);
		}
		
		function login()
		{
		
			return $this->_oauth->login();
		}
		
		function logout()
		{
			return $this->_oauth->logout();
		}
		
		function get_tokens()
		{
			$tokens = array(
							'oauth_token' => $this->_oauth->getAccessKey(),
							'oauth_token_secret' => $this->_oauth->getAccessSecret()
						);
						
			return $tokens;
		}
		
		function set_tokens($tokens)
		{
			return $this->_oauth->setAccessTokens($tokens);
		}
		function set_status($update_str){
		
			//$update_str= htmlentities($update_str);
			
			$this->call('post', 'statuses/update', array('status' => $update_str));
			
		return;
		}
	}
	
	class tweetException extends Exception {
		
		function __construct($string)
		{
			parent::__construct($string);
		}
		
		public function __toString() {
			return "exception '".__CLASS__ ."' with message '".$this->getMessage()."' in ".$this->getFile().":".$this->getLine()."\nStack trace:\n".$this->getTraceAsString();
		}
	}
	
	class tweetConnection {
		
		// Allow multi-threading.
		
		private $_mch = NULL;
		private $_properties = array();
		
		function __construct()
		{
			$this->_mch = curl_multi_init();
			
			$this->_properties = array(
				'code' 		=> CURLINFO_HTTP_CODE,
				'time' 		=> CURLINFO_TOTAL_TIME,
				'length'	=> CURLINFO_CONTENT_LENGTH_DOWNLOAD,
				'type' 		=> CURLINFO_CONTENT_TYPE
			);
		}
		
		private function _initConnection($url)
		{
			$this->_ch = curl_init($url);
			curl_setopt($this->_ch, CURLOPT_RETURNTRANSFER, TRUE);
		}
		
		public function get($url, $params)
		{
			if ( count($params['request']) > 0 )
			{//print_r($params);
				$url .= '?'.http_build_query($params['request']);
			}
			//echo $url;
			//print_r($params);
			$this->_initConnection($url);
			
			$response = $this->_addCurl($url, $params);


//echo "response: ";print_r($response);
		    return $response;
		}
		
		public function post($url, $params)
		{
			// Todo
			$urlParts = parse_url($url);
			$scheme = strtolower($urlParts['scheme']);
			echo '<h3> Posting</h3>';
			  //
			
			var_dump($params);
			if ($scheme == "http"){
				$post = http_build_query($params['request']);
				//$url.= '?'. $post;
			}
			$this->_initConnection($url);
			curl_setopt($this->_ch, CURLOPT_POST, 1);
			if ($scheme == "http"){
				curl_setopt($this->_ch, CURLOPT_POSTFIELDS, $post);
			}
			curl_setopt($this->_ch, CURLOPT_VERBOSE, true);
			$response = $this->_addCurl($url, $params);
			//echo '<h1> Response for access</h1>';
			//var_dump($response);
		    return $response;
		}
		
		private function _addOauthHeaders(&$ch, $url, $oauthHeaders)
		{
			$_h = array('Expect:');
			$urlParts = parse_url($url);
		
			$oauth = 'Authorization: OAuth realm="http://' . $urlParts['host'] . '",';
			
			foreach ( $oauthHeaders as $name => $value )
			{
				$oauth .= "{$name}=\"{$value}\",";
			}
		
			$_h[] = substr($oauth, 0, -1);
			//echo '<h2>headers</h2>';
			//print_r($_h);
			curl_setopt($ch, CURLOPT_HTTPHEADER, $_h);
		}
		
		private function _addCurl($url, $params = array())
		{	echo "<h2>CURL'g ".$url.'</h2>';
			if ( !empty($params['oauth']) )
			{
				if ( !empty($params['request']) ){
					foreach ($params['request'] as $key => $val){
					$params['oauth'][$key] = $val;
					
					}
				
				}
				$this->_addOauthHeaders($this->_ch, $url, $params['oauth']);
			}
		
			
			$ch = $this->_ch;
	
			$key = (string) $ch;
			
			$this->_requests[$key] = $ch;
		
			$response = curl_multi_add_handle($this->_mch, $ch);
		
			if ( $response === CURLM_OK || $response === CURLM_CALL_MULTI_PERFORM )
			{ 
				do { //echo "working";
					$mch = curl_multi_exec($this->_mch, $active);
					
				} while ( $mch === CURLM_CALL_MULTI_PERFORM );
				
				return $this->_getResponse($key);
			}
			else
			{
				return $response;
			}
		}
		
		private function _getResponse($key = NULL)
		{
			if ( $key == NULL ) return FALSE;
			
			if ( isset($this->_responses[$key]) )
			{
				return $this->_responses[$key];
			}
			
			$running = NULL;
			
			do
			{
				$response = curl_multi_exec($this->_mch, $running_curl);
				
				if ( $running !== NULL && $running_curl != $running )
				{
					$this->_setResponse($key);
					
					if ( isset($this->_responses[$key]) )
					{
						$response = new tweetResponseOauth( (object) $this->_responses[$key] );
						//var_dump($response->__resp);
						if ( $response->__resp->code !== 200 )
						{
						var_dump($response->__resp);
							throw new tweetException($response->__resp->code.' | Request Failed: '.$response->__resp->data->request.' - '.$response->__resp->data->error);
						}
						
						return $response;
					}
				}
				
				$running = $running_curl;
				
			} while ( $running_curl > 0);
			
		}
		
		private function _setResponse($key)
		{
			while( $done = curl_multi_info_read($this->_mch) )
			{
				$key = (string) $done['handle'];
				$this->_responses[$key]['data'] = curl_multi_getcontent($done['handle']);
				
				foreach ( $this->_properties as $curl_key => $value )
				{
					$this->_responses[$key][$curl_key] = curl_getinfo($done['handle'], $value);
					
					curl_multi_remove_handle($this->_mch, $done['handle']);
				}
		  }
		}
	}
	
	class tweetResponseOauth {
		
		private $__construct;

		public function __construct($resp)
		{
			$this->__resp = $resp;

			if ( strpos($this->__resp->type, 'json') !== FALSE )
			{
				$this->__resp->data = json_decode($this->__resp->data);
			}
		}

		public function __get($name)
		{ //var_dump($this->__resp);
			if ($this->__resp->code < 200 || $this->__resp->code > 299) return FALSE;
			
			if ( is_string($this->__resp->data ) )
			{
				parse_str($this->__resp->data, $result);
			}
			else
			{
				$result = $this->__resp->data;
			}
			
			foreach($result as $k => $v)
			{
				$this->$k = $v;
			}
			
			if ( $name === '_result')
			{
				return $result;
			}

			return $result[$name];
		}
	}
	
	class tweetOauth extends tweetConnection {
		
		private $_obj;
		private $_tokens = array();
		private $_authorizationUrl 	= 'https://api.twitter.com/oauth/authenticate';
		private $_requestTokenUrl 	= 'https://api.twitter.com/oauth/request_token';
		private $_accessTokenUrl 	= 'https://api.twitter.com/oauth/access_token';
		private $_signatureMethod 	= 'HMAC-SHA1';
		private $_version 			= '1.0';
		private $_apiUrl 			= 'http://api.twitter.com/1';
		private $_searchUrl			= 'http://search.twitter.com/';
		private $_callback = NULL;
		private $_errors = array();
		private $_enable_debug = TRUE;
		
		function __construct()
		{
			parent::__construct();
			
			$this->_obj =& get_instance();
			$this->_obj->load->config('tweet');
			$this->_obj->load->library('session');
			$this->_obj->load->library('unit_test');
			$this->_obj->load->helper('url');
			
			$this->_tokens =	array(
									'consumer_key' 		=> $this->_obj->config->item('tweet_consumer_key'),
									'consumer_secret' 	=> $this->_obj->config->item('tweet_consumer_secret'),
									'access_key'		=> $this->_getAccessKey(),
									'access_secret' 	=> $this->_getAccessSecret()
								);
								
			$this->_checkLogin();
		}
		
		function __destruct()
		{
			if ( !$this->_enable_debug ) return;
			
			if ( !empty($this->_errors) )
			{
				foreach ( $this->_errors as $key => $e )
				{
					echo '<pre>'.$e.'</pre>';
				}
			}
		}
		
		public function enable_debug($debug)
		{
			$debug = (bool) $debug;
			$this->_enable_debug = $debug;
		}
		
		public function call($method, $path, $args = NULL)
		{
			$response = $this->_httpRequest(strtoupper($method), $this->_apiUrl.'/'.$path.'.json', $args);
			
			// var_dump($response);
			// die();
			
			return ( $response === NULL ) ? FALSE : $response->_result;
		}
		
		public function search($args = NULL)
		{
			$response = $this->_httpRequest('GET', $this->_searchUrl.'search.json', $args);
			
			return ( $response === NULL ) ? FALSE : $response->_result;
		}
		
		public function loggedIn()
		{
	
			$access_key = $this->_getAccessKey();
			$access_secret = $this->_getAccessSecret();
			$token_secret = $this->_getTokenSecret();

			$loggedIn = FALSE;
			echo "You are not logged in yet <br/>";
			if ( $this->_getAccessAuthKey() !== NULL )
			{
				echo "You are logged in:". $this->_getAccessAuthKey();
				$loggedIn = TRUE;
			}
			
			$this->_obj->unit->run($loggedIn, TRUE, 'Logged In');
			return $loggedIn;
		}
		
		private function _checkLogin()
		{
		
			if ( $this->_getAccessKey() !== NULL && $this->_getAccessSecret() !== NULL && $this->_getTokenSecret() !== NULL && $this->_getAccessAuthKey()== NULL){
				//echo "second called";
			$access = $this->_getAccessToken();
			//echo '<br/>access';
			//var_dump($access); echo '<br/>';
				//echo "second called";
			$tokens=$access->__resp->data;
			
			parse_str($tokens, $return_stuff);
			
			//print_r($return_stuff);
			
			//$this->_setAccessAuthKey($return_stuff['oauth_token']);
			
			$this->_setAccessKey($return_stuff['oauth_token']);
			$this->_setAccessSecret($return_stuff['oauth_token_secret']);
			unset($return_stuff['oauth_token']);
			unset($return_stuff['oauth_token_secret']);
			
			reset($return_stuff);
			while (list($key, $val) = each($return_stuff)) {
  				$this->_setUserData($key, $val);
			}
			return TRUE;
		}
			
				
			 else if ( isset($_GET['oauth_token']) && $this->_getAccessSecret() == NULL)
			{ 
				
				//$token = $this->_getRequestToken();
			
			//	$token = $token->_result;
				//echo "first called";
				//$token = ( is_bool($token) ) ? $token : (object) $token;
				
				//if ( !empty($token->oauth_token) && !empty($token->oauth_token_secret) && !empty($token->oauth_token_secret))
				//{
					//$this->_setAccessKey($token->oauth_token);
				//$getVars = split('\?',$_SERVER['REQUEST_URI']);
  			//$varArray = split('&',$getVars[1]);
  			//$tokenstring = split('=',$varArray[0]);
  			//$verifierstring = split('=',$varArray[1]);
  			//$_GET['oauth_token'] = $tokenstring[1];
  			//$_GET['oauth_verifier'] = $verifierstring[1];
  			//$oauth_token_secret = $verifierstring[1];
  			$tokens = array('oauth_token' => $_GET['oauth_token'], 'oauth_token_secret' => $_GET['oauth_verifier'] );				//}
				
				print_r($tokens);
				$this->_setAccessKey($_GET['oauth_token']);
				$this->_setAccessSecret($_GET['oauth_verifier']);
				$this->_checkLogin();
				}
		}
		public function login()
		{
			
		
			if ( ($this->_getAccessKey() === NULL) )
			{ 
			echo "login is called.";
			$token = $this->_getRequestToken();
			$return_data = $token->__resp->data;
			//echo "Token var:".$return_data;
			parse_str($return_data, $return_stuff);
			
			//print_r($return_stuff);
			
			$token_secret = $return_stuff['oauth_token_secret'];
			$this-> _setAccessKey($return_stuff['oauth_token']);	
			$this->setTokenSecret($token_secret);
		
				header('Location: '.$this->_getAuthorizationUrl());
				return;
			}
			
			return $this->_checkLogin();
		}
		
		public function logout()
		{
			$this->_obj->session->unset_userdata('twitter_oauth_tokens');
		}
		
		public function getTokens()
		{
			return $this->_tokens;
		}
		
		private function _getConsumerKey()
		{
			return $this->_tokens['consumer_key'];
		}
		
		private function _getConsumerSecret()
		{
			return $this->_tokens['consumer_secret'];
		}
		
		public function getAccessKey(){ return $this->_getAccessKey(); }
		
		private function _getAccessKey()
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			return ( $tokens === FALSE || !isset($tokens['access_key']) || empty($tokens['access_key']) ) ? NULL : $tokens['access_key'];
		}
		private function _setUserData($name, $value)
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			if ( $tokens === FALSE || !is_array($tokens) )
			{
				$tokens = array($name => $value);
			}
			else
			{
				$tokens[$name] = $value;
			}
			
			$this->_obj->session->set_userdata('twitter_oauth_tokens', $tokens);
		}
		public function getAccessAuthKey(){ return $this->_getAccessAuthKey(); }
		
		private function _getAccessAuthKey()
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			return ( $tokens === FALSE || !isset($tokens['access_auth_key']) || empty($tokens['access_auth_key']) ) ? NULL : $tokens['access_auth_key'];
		}
		
		private function _setAccessKey($access_key)
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			if ( $tokens === FALSE || !is_array($tokens) )
			{ 
				$tokens = array('access_key' => $access_key);
			}
			else
			{
				$tokens['access_key'] = $access_key;
			}
			
			$this->_obj->session->set_userdata('twitter_oauth_tokens', $tokens);
		}
		private function _setAccessAuthKey($access_auth_key)
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			if ( $tokens === FALSE || !is_array($tokens) )
			{
				$tokens = array('access_auth_key' => $access_auth_key);
			}
			else
			{
				$tokens['access_auth_key'] = $access_auth_key;
			}
			
			$this->_obj->session->set_userdata('twitter_oauth_tokens', $tokens);
		}
		private function _setAccessAuthSecret($access_auth_secret)
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			if ( $tokens === FALSE || !is_array($tokens) )
			{
				$tokens = array('access_auth_key' => $access_auth_secret);
			}
			else
			{
				$tokens['access_auth_key'] = $access_auth_secret;
			}
			
			$this->_obj->session->set_userdata('twitter_oauth_tokens', $tokens);
		}
		public function getAccessSecret(){ return $this->_getAccessSecret(); }
		
		private function _getAccessSecret()
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			return ( $tokens === FALSE || !isset($tokens['access_secret']) || empty($tokens['access_secret']) ) ? NULL : $tokens['access_secret'];
		}
		
		private function _setAccessSecret($access_secret)
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			if ( $tokens === FALSE || !is_array($tokens) )
			{
				$tokens = array('access_secret' => $access_secret);
			}
			else
			{
				$tokens['access_secret'] = $access_secret;
			}
			
			$this->_obj->session->set_userdata('twitter_oauth_tokens', $tokens);
		}
		
		public function setTokenSecret($token_secret){ return $this->_setTokenSecret($token_secret); }
		
		private function _setTokenSecret($token_secret)
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			if ( $tokens === FALSE || !is_array($tokens) )
			{
				//$tokens = array('token_secret' => $token_secret);
				$this->_obj->session->set_userdata('token_secret', $token_secret);
				//Don't set as oauth tokens yet.
			}
			else
			{
				
				$tokens['token_secret'] = $token_secret;
				$this->_obj->session->set_userdata('twitter_oauth_tokens', $tokens);
				//echo "Token secret set";
				//$this->session->unset_userdata('token_secret');
			}
			return TRUE;
			
		}
		public function getTokenSecret(){ return $this->_getTokenSecret(); }
		
		private function _getTokenSecret()
		{	
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			if ( $tokens === FALSE || !is_array($tokens) )
			{
			$token_secret = $this->_obj->session->userdata('token_secret');
			return $token_secret;
			} else{
			return ( $tokens === FALSE || !isset($tokens['token_secret']) || empty($tokens['token_secret']) ) ? NULL : $tokens['token_secret'];
			}
			
		}
		private function _setAccessTokens($tokens)
		{	echo "bully!";
			$this->_setAccessKey($tokens['oauth_token']);
			$this->_setAccessSecret($tokens['oauth_token_secret']);
			//$this->_setTokenSecret($this->_obj->session->userdata('token_secret'));
		}
		
		public function setAccessTokens($tokens)
		{
			return $this->_setAccessTokens($tokens);
		}
		
		private function _getAuthorizationUrl()
		{

			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			return $this->_authorizationUrl.'?oauth_token=' . $tokens['access_key'];
		}
		
		private function _getRequestToken()
		{
			return $this->_httpRequest('POST', $this->_requestTokenUrl);
		}
		
		private function _getAccessToken()
		{
			return $this->_httpRequest('POST', $this->_accessTokenUrl);
		}
		
		protected function _httpRequest($method = null, $url = null, $params = null)
		{
			if( empty($method) || empty($url) ) return FALSE;
			if ( empty($params['oauth_signature']) ) $params = $this->_prepareParameters($method, $url, $params);
			
			$this->_connection = new tweetConnection();
			
			try {
				switch ( $method )
				{
					case 'GET':
						return $this->_connection->get($url, $params);
					break;

					case 'POST':
						//var_dump($url);
						//echo '<br/>';
						//var_dump($params);
						//echo '<br/>';
						return $this->_connection->post($url, $params);
					break;

					case 'PUT':
						return NULL;
					break;

					case 'DELETE':
						return NULL;
					break;
				}
			} catch (tweetException $e) {
				$this->_errors[] = $e;
			}
		}
		
		private function _getCallback()
		{
			return $this->_callback;
		}
		
		public function setCallback($url)
		{
			$this->_callback = $url;
		}
		
		private function _prepareParameters($method = NULL, $url = NULL, $params = NULL)
		{
			if ( empty($method) || empty($url) ) return FALSE;
			
			$callback = $this->_getCallback();
			
			if ( !empty($callback) )
			{
				$oauth['oauth_callback'] = $callback;
			}
			
			$this->setCallback(NULL);
			
			$oauth['oauth_consumer_key'] 		= $this->_getConsumerKey();
			$oauth['oauth_token'] 				= $this->_getAccessKey();
			$oauth['oauth_nonce'] 				= $this->_generateNonce();
			$oauth['oauth_timestamp'] 			= time();
			$oauth['oauth_signature_method'] 	= $this->_signatureMethod;
			$oauth['oauth_verifier'] 			= $this->_getAccessSecret();
			$oauth['oauth_version'] 			= $this->_version;
			
			if($url==$this->_requestTokenUrl){
			
			unset($oauth['oauth_token']);
			unset($oauth['oauth_verifier']);
			}
			
			
			array_walk($oauth, array($this, '_encode_rfc3986'));
			
			if ( is_array($params) )
			{
				array_walk($params, array($this, '_encode_rfc3986'));
			}
			
			$encodedParams = array_merge($oauth, (array)$params);
			
			ksort($encodedParams);
			
			$oauth['oauth_signature'] = $this->_encode_rfc3986($this->_generateSignature($method, $url, $encodedParams));
			
			return array('request' => $params, 'oauth' => $oauth);
		}
	
		private function _generateNonce()
		{
			return md5(uniqid(rand(), TRUE));
		}
		
		private function _encode_rfc3986($string)
		{
			return str_replace('+', ' ', str_replace('%7E', '~', rawurlencode(($string))));
		}
		
		private function _generateSignature($method = null, $url = null, $params = null)
		{
			if( empty($method) || empty($url) ) return FALSE;
			
			// concatenating
			$concatenatedParams = '';
			if($url==$this->_requestTokenUrl){
			//Twitter needs the oauth callback to be double-encoded
			
				$params['oauth_callback']=$this->_encode_rfc3986(urlencode($params['oauth_callback']));
			
			//For Request Tokens, remove any oauth_token and oauth_token_secret from the string
			
				unset($params['oauth_token']);
				unset($params['oauth_verifier']);
			}
			
			
			foreach ($params as $k => $v)
			{
				//$v = $this->_encode_rfc3986($v);
				$concatenatedParams .= "{$k}%3D{$v}%26";
			}
			$concatenatedParams = substr($concatenatedParams, 0, -3);
			//echo 'Before: ' .$concatenatedParams.'<br/>';
			//$concatenatedParams = $this->_encode_rfc3986(substr($concatenatedParams, 0, -1));
			//echo 'after: ' .$concatenatedParams.'<br/>';
			// normalize url
			$normalizedUrl = $this->_encode_rfc3986($this->_normalizeUrl($url));
			
			
			$method = $this->_encode_rfc3986($method); // don't need this but why not?

			$signatureBaseString = "{$method}&{$normalizedUrl}&{$concatenatedParams}";
			//echo $signatureBaseString;
			$urlParts = parse_url($url);
			
			if($scheme = strtolower($urlParts['scheme'])=="http"){
			
			return $this->_signString($signatureBaseString, 'api');
			
			} else{
			
			return $this->_signString($signatureBaseString, 'auth');
			}
			
			
		}
		
		private function _normalizeUrl($url = NULL)
		{
			$urlParts = parse_url($url);

			if ( !isset($urlParts['port']) ) $urlParts['port'] = 80;

			$scheme = strtolower($urlParts['scheme']);
			$host = strtolower($urlParts['host']);
			$port = intval($urlParts['port']);

			$retval = "{$scheme}://{$host}";
			
			if ( $port > 0 && ( $scheme === 'http' && $port !== 80 ) || ( $scheme === 'https' && $port !== 443 ) )
			{
				//$retval .= ":{$port}";
			}
			
			$retval .= $urlParts['path'];
			
			if ( !empty($urlParts['query']) )
			{
				$retval .= "?{$urlParts['query']}";
			}
			
			return $retval;
		}
		
		private function _signString($string, $where)
		{
			$retval = FALSE;
			switch ( $this->_signatureMethod )
			{
				case 'HMAC-SHA1':
					$key = $this->_encode_rfc3986($this->_getConsumerSecret()) . '&'; 
					
					if ($where== 'api'){
					
					$key .=  $this->_encode_rfc3986($this->_getAccessSecret());
					
					} else {
					$key .=  $this->_encode_rfc3986($this->_getTokenSecret());
					
					
					}
					//echo "<br/>Key: ".$key.'<br/>';
					$retval = base64_encode(hash_hmac('sha1', $string, $key, true));
					//echo '<br/>retval: '.$retval.'<br/>';
				break;
			}

			return $retval;
		}

	}