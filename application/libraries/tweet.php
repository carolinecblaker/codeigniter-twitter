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
		function get_request_secret()
		{
			return $this->_oauth->getRequestSecret();
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
			{
				$url .= '?'.http_build_query($params['request']);
			}
			
			$this->_initConnection($url);
			
			$response = $this->_addCurl($url, $params);

		    return $response;
		}
		
		public function post($url, $params)
		{
			$urlParts = parse_url($url);
			
			$scheme = strtolower($urlParts['scheme']);
			
			if ($scheme == "http"){
			
				$post = http_build_query($params['request']);
			
			}
			
			$this->_initConnection($url);
			
			curl_setopt($this->_ch, CURLOPT_POST, 1);
			
			if ($scheme == "http"){
			
				curl_setopt($this->_ch, CURLOPT_POSTFIELDS, $post);
			}
			curl_setopt($this->_ch, CURLOPT_VERBOSE, true);
			
			$response = $this->_addCurl($url, $params);

		    return $response;
		}
		
		private function _addOauthHeaders(&$ch, $url, $oauthHeaders)
		{
			$_h = array('Expect:');
			
			$urlParts = parse_url($url);
		
			$oauth = 'Authorization: OAuth realm="http://' . $urlParts['host'] . '",';
			
			foreach ( $oauthHeaders as $name => $value )
			{
				if($name !="status"){
				
				$oauth .= "{$name}=\"{$value}\",";
				
				}
			}
		
			$_h[] = substr($oauth, 0, -1);

			curl_setopt($ch, CURLOPT_HTTPHEADER, $_h);
		}
		
		private function _addCurl($url, $params = array())
		{	
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
				do {
				
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
		{ 
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
		private $_defaultCallback   = 'tweet_test/auth';
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
			
			return ( $response === NULL ) ? FALSE : $response->_result;
		}
		
		public function search($args = NULL)
		{
			$response = $this->_httpRequest('GET', $this->_searchUrl.'search.json', $args);
			
			return ( $response === NULL ) ? FALSE : $response->_result;
		}
		
		public function loggedIn()
		{
			if ($this->_getAccessSecret() && $this->_getAccessKey()){
		
				$user = $this->call('get', 'account/verify_credentials');
				
				if ( isset($user->profile_text_color) )
						{
							$loggedIn = TRUE;
						
						} else{
					
							$loggedIn = FALSE;
													}
				} else{			
		
					$loggedIn = FALSE;
				
				}
			
				return $loggedIn;
			}
		
		private function _checkLogin()
		
		{
		//Drilldown
		if ($this->loggedIn()=== FALSE){
				
		if ( $this->_getAccessVerifier()!==NULL )
		
		{ 

			echo $this->_getAccessVerifier();	
				
  			$access = $this->_getAccessToken();
  			
			$tokens=$access->__resp->data;
			
			parse_str($tokens, $data);
			
			$this->_setAccessKey($data['oauth_token']);
			$this->_setAccessSecret($data['oauth_token_secret']);
			$this->_setUserData('screen_name',$data['screen_name'] );
			$this->_setUserData('user_id',$data['user_id'] );
			 
			 return;
			} else if ($this->_getRequestSecret() !== NULL){
					
			//pass through back to CONTROLLER for setting of GET vars
			
			return;
			
			} else{
						
				$this->login();
				
			}
		} else{
				
			return;
		}
		}
		public function login($var = FALSE)
		{
			if ($this->_getRequestAuthToken() === NULL) 
			{ 
			
			$token = $this->_getRequestToken();
			
			$return_data = $token->__resp->data;
		
			parse_str($return_data, $return_stuff);
			
			$token_secret = $return_stuff['oauth_token_secret'];
			
			$this->_setRequestToken($return_stuff['oauth_token']);
				
			$this->_setRequestSecret($token_secret);

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
		public function unsetToken($token){ return $this->_unsetToken($token); }
		
		private function _unsetToken($token){
		
	
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			if ( $tokens === FALSE || !is_array($tokens) )
			{
				return;
			}
			else if (isset($tokens[$token]))
			{
				
				
				unset($tokens[$token]);
			}
			
			$this->_obj->session->set_userdata('twitter_oauth_tokens', $tokens);
		
		}
	
		private function _getConsumerKey()
		{
			return $this->_tokens['consumer_key'];
		}
		
		private function _getConsumerSecret()
		{
			return $this->_tokens['consumer_secret'];
		}
		public function getRequestToken(){ return $this->_getRequestAuthToken(); }
		
		private function _getRequestAuthToken()
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			return ( $tokens === FALSE || !isset($tokens['request_token']) || empty($tokens['request_token']) ) ? NULL : $tokens['request_token'];
		}
		
	
		private function _setRequestToken($request_token)
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			if ( $tokens === FALSE || !is_array($tokens) )
			{
				$tokens = array('request_token' => $request_token);
			}
			else
			{
				$tokens['request_token'] = $request_token;
			}
			
			$this->_obj->session->set_userdata('twitter_oauth_tokens', $tokens);
		}
		public function getRequestSecret(){ return $this->_getRequestSecret(); }
		
		private function _getRequestSecret()
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			return ( $tokens === FALSE || !isset($tokens['request_secret']) || empty($tokens['request_secret']) ) ? NULL : $tokens['request_secret'];
		}

		private function _setRequestSecret($request_secret)
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			if ( $tokens === FALSE || !is_array($tokens) )
			{
				$tokens = array('request_secret' => $request_secret);
			}
			else
			{
				$tokens['request_secret'] = $request_secret;
			}
			
			$this->_obj->session->set_userdata('twitter_oauth_tokens', $tokens);
			
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
		private function _setAccessVerifier($access_verifier)
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			if ( $tokens === FALSE || !is_array($tokens) )
			{ 
				$tokens = array('access_verifier' => $access_verifier);
			}
			else
			{
				$tokens['access_verifier'] = $access_verifier;
			}
			
			$this->_obj->session->set_userdata('twitter_oauth_tokens', $tokens);
		}
		public function getAccessVerifier(){ return $this->_getAccessVerifier(); }
		
		private function _getAccessVerifier()
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			return ( $tokens === FALSE || !isset($tokens['access_verifier']) || empty($tokens['access_verifier']) ) ? NULL : $tokens['access_verifier'];
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
				
				$this->_obj->session->set_userdata('token_secret', $token_secret);
				
			}
			else
			{
				$tokens['token_secret'] = $token_secret;
				
				$this->_obj->session->set_userdata('twitter_oauth_tokens', $tokens);
				
			}
			
			return TRUE;
			
		}
		public function getTokenSecret(){ return $this->_getTokenSecret(); }
		
		private function _getTokenSecret()
		{	
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			if ( $tokens === FALSE || !is_array($tokens) ){
			
			$token_secret = $this->_obj->session->userdata('token_secret');
			
			return $token_secret;
			
			} else{
			
			return ( $tokens === FALSE || !isset($tokens['token_secret']) || empty($tokens['token_secret']) ) ? NULL : $tokens['token_secret'];
			
			}
			
		}
		private function _setAccessTokens($tokens)
		{
			//Can check here to see if $tokens['access_token'] == getRequestToken();
			
			$this->_setAccessVerifier($tokens['access_verifier']);
			//$this->_setTokenSecret($this->_obj->session->userdata('token_secret'));<-- using the same record as is sent on Request instead of creating new label
		}
		
		public function setAccessTokens($tokens)
		{
			return $this->_setAccessTokens($tokens);
		}
		
		private function _getAuthorizationUrl()
		{

			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			return $this->_authorizationUrl.'?oauth_token=' . $tokens['request_token'];
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
			
			if ( empty($params['oauth_signature']) || isset($params['status'])){ $params = $this->_prepareParameters($method, $url, $params);}
			
			$this->_connection = new tweetConnection();
			
			try {
				switch ( $method )
				{
					case 'GET':
						return $this->_connection->get($url, $params);
					break;

					case 'POST':
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
				
			} else if ($url==$this->_requestTokenUrl){
			
			$oauth['oauth_callback']= site_url($this->_defaultCallback);
			
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
			else	if($url==$this->_accessTokenUrl){
			
				$oauth['oauth_verifier'] 			= $this->_getAccessVerifier();	
				$oauth['oauth_token'] 				= $this->_getRequestAuthToken();
				
			
			}
			 else if ($url==$this->_apiUrl.'/statuses/update.json'){
			
		;
					unset($oauth['oauth_verifier']);
			}
			
			
			array_walk($oauth, array($this, '_encode_rfc3986'));
			
			if ( is_array($params) )
			{
				array_walk($params, array($this, '_encode_rfc3986'));
			}
			
			$encodedParams = array_merge($oauth, (array)$params);
			
			ksort($encodedParams);
			
			if (isset($encodedParams['status'])){
			
				$encodedParams['status']=urlencode($params['status']);
			
			}
			//var_dump($encodedParams);
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
				
				$concatenatedParams .= "{$k}%3D{$v}%26";
			}
			$concatenatedParams = substr($concatenatedParams, 0, -3);
			
			$normalizedUrl = $this->_encode_rfc3986($this->_normalizeUrl($url));
			
			
			$method = $this->_encode_rfc3986($method); // don't need this but why not?

			$signatureBaseString = "{$method}&{$normalizedUrl}&{$concatenatedParams}";
			//if ($url==$this->_apiUrl.'/statuses/update.json'){
			//echo "<h3>".$signatureBaseString."</h3>";
			//}
			$urlParts = parse_url($url);
			
			if($scheme = strtolower(($urlParts['scheme'])=="http") && ($url!=$this->_apiUrl.'/statuses/update.json')){
			
			return $this->_signString($signatureBaseString, 'api');
			
			}else if($url == $this->_accessTokenUrl ){
			
			return $this->_signString($signatureBaseString, 'access');
			
			} 
			
			else{
			
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
					
					if ($where== 'api' || $where=='auth'){
					//echo "<h2>API</h2>";
					$key .=  $this->_encode_rfc3986($this->_getAccessSecret());
					}
					else if ($where== 'access'){
					//echo "<h2>API</h2>";
					$key .=  $this->_encode_rfc3986($this->_getAccessVerifier());
					
					
					} else {
					$key .=  $this->_encode_rfc3986($this->_getTokenSecret());
					//echo '<h3>key other side</h3>';
					
					}
					//echo "<br/>Key: ".$key.'<br/>';
					$retval = base64_encode(hash_hmac('sha1', $string, $key, true));
					//echo '<br/>retval: '.$retval.'<br/>';
				break;
			}

			return $retval;
		}

	}