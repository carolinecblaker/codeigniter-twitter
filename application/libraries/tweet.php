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
		{/* OLD GET REQUEST*/
	
			if ( count($params['request']) > 0 )
	
	
			{
				$url .= '?';
			
				foreach( $params['request'] as $k => $v )
				{
				
					$url .= "{$k}={$v}&";
				}
				
				$url = substr($url, 0, -1);

			}

	
			$this->_initConnection($url);
			
			
			if ( count($params['request']) > 0 ){
			//echo"GOT"; exit;
			//	curl_setopt($this->_ch, CURLOPT_HTTPGET, 1);
			//curl_setopt($this->_ch, CURLOPT_POSTFIELDS, $post);
				
				}
			$response = $this->_addCurl($url, $params);
			
			
		    return $response;
		}
		
		public function post($url, $params)
		{
			// Todo
			$post = ''; 
			if (isset($params['request'])){
				foreach ( $params['request'] as $k => $v )
				{
				$post .= "{$k}={$v}&";
				}
			}
			$post = substr($post, 0, -1);
			
			$this->_initConnection($url, $params);
			curl_setopt($this->_ch, CURLOPT_POST, 1);
			curl_setopt($this->_ch, CURLOPT_POSTFIELDS, $post);
			
			$response = $this->_addCurl($url, $params);

			 return $response;
		}
		
		private function _addOauthHeaders(&$ch, $url, $oauthHeaders)
		{
			$_h = array('Expect:');
			$urlParts = parse_url($url);
	
			$oauth = 'Authorization: OAuth ';
			foreach ( $oauthHeaders as $name => $value )
			{
				$oauth .= "{$name}=\"{$value}\",";
			}
			
			$_h[] = substr($oauth, 0, -1);
			$log_headers = var_export($oauth, TRUE); 
			$log_headers = str_replace(array("\r","\n"), '', $log_headers); 
					log_message('debug', 'Oauth URL: '. $url);
					log_message('debug', 'Oauth Headers: '. $log_headers);

	
			curl_setopt($ch, CURLOPT_HTTPHEADER, $_h);
		}
		
		private function _addCurl($url, $params = array())
		{	
			if ( !empty($params['oauth']) )
			{
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
				
							 log_message('error', 'Feed not pulled: '. $response->__resp->data->errors[0]->message. ' Code:'.$response->__resp->code);	
							//throw new tweetException($response->__resp->code.' | Request Failed: '.$response->__resp->data.' - '.$response->__resp->data->errors);
						
							
						}
						//echo "<h1>Response</h1>";
						//print_r($response);
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
		private $_authorizationUrl 	= 'https://api.twitter.com/oauth/authorize';
		private $_requestTokenUrl 	= 'https://api.twitter.com/oauth/request_token';
		private $_accessTokenUrl 	= 'https://api.twitter.com/oauth/access_token';
		private $_signatureMethod 	= 'HMAC-SHA1';
		private $_version 			= '1.0'; /*This is the oAuth version*/
		private $_apiUrl 			= 'https://api.twitter.com/1.1'; /*This is the API version*/
		private $_callback = NULL;
		private $_errors = array();
		private $_enable_debug = FALSE;
		
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
									'access_secret' 	=> $this->_getAccessSecret(),
									'access_verifier' 	=> $this->_getAccessVerifier()
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

			if (isset($response->__resp->code) && $response->__resp->code ===200 ){

				$returnvar= $response->_result;
			}
			else {
				$returnvar =$response;
			}	
		
			return $returnvar;
		}
		
		
		public function loggedIn()
		{
			$access_key = $this->_getAccessKey();
			$access_secret = $this->_getAccessSecret();
			
			$loggedIn = FALSE;
			
			if ( $this->_getAccessKey() !== NULL && $this->_getAccessSecret() !== NULL )
			{
				$loggedIn = TRUE;
			}
			
		
			$this->_obj->unit->run($loggedIn, TRUE, 'Logged In');
			return $loggedIn;
		}
		
		private function _checkLogin()
		{
		
			$getVars = preg_split('[\?]',$_SERVER['REQUEST_URI']);
			
			if ( isset($getVars[1]) ) 
			{
			$varArray = preg_split('[&]',$getVars[1]);
			
  			$tokenstring = preg_split('[=]',$varArray[0]);
  			$verifier = preg_split('[=]',$varArray[1]);
  			
			if ( isset($tokenstring) && isset ($verifier) )
			{

				$this->_setAccessKey($tokenstring[1]);
				
				$this->_setAccessVerifier($verifier[1]);
				
				$token = $this->_getAccessToken();
				
				
				$token = $token->_result;
				
				$token = ( is_bool($token) ) ? $token : (object) $token;
				
				if ( !empty($token->oauth_token) && !empty($token->oauth_token_secret) )
				{
					$this->_setAccessKey($token->oauth_token);
					$this->_setAccessSecret($token->oauth_token_secret);
				}
				
				redirect(current_url());
				return NULL;
			}
			} else {}
		}
		
		public function login()
		{
			if ( ($this->_getAccessKey() === NULL && $this->_getAccessSecret() === NULL) )
			{  
				
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
		
		public function getAccessVerifier(){ return $this->_getAccessVerifier(); }
		
		private function _getAccessVerifier()
		{
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			return ( $tokens === FALSE || !isset($tokens['verifier']) || empty($tokens['verifier']) ) ? NULL : $tokens['verifier'];
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
		
		private function _setAccessVerifier($verifier){
			
			$tokens = $this->_obj->session->userdata('twitter_oauth_tokens');
			
			if ( $tokens === FALSE || !is_array($tokens) )
			{
				$tokens = array('verifier' => $verifier);
			}
			else
			{
				$tokens['verifier'] = $verifier;
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
		
		private function _setAccessTokens($tokens)
		{
			$this->_setAccessKey($tokens['oauth_token']);
			$this->_setAccessSecret($tokens['oauth_token_secret']);
		}
		
		public function setAccessTokens($tokens)
		{
			return $this->_setAccessTokens($tokens);
		}
		
		private function _getAuthorizationUrl()
		{
			$token = $this->_getRequestToken();
			
			return $this->_authorizationUrl.'?oauth_token=' . $token->oauth_token;
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
			if ($url == $this->_accessTokenUrl) {
			
		
				
			 	
			}
		
			$this->_connection = new tweetConnection();

			$log_params = var_export($params, TRUE); 
			
			$log_params = str_replace(array("\r","\n"), '', $log_params); 

			try {
				switch ( $method )
				{
					case 'GET':
					 log_message('debug', 'GET request::');
						return $this->_connection->get($url, $params);
					break;

					case 'POST':
					 log_message('debug','THIS IS A POST');
						 log_message('debug', 'POST request:: ');
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
			//	$oauth['oauth_callback'] = urlencode($callback); //Request token issue added urlencode() 3/18/2015
				$oauth['oauth_callback'] = $callback;
			}
			
			$this->setCallback(NULL);
			#Content-Type: application/x-www-form-urlencoded
			$oauth['oauth_consumer_key'] 		= $this->_getConsumerKey();
			$oauth['oauth_token'] 				= $this->_getAccessKey();
			$oauth['oauth_nonce'] 				= $this->_generateNonce();
			$oauth['oauth_timestamp'] 			= time();
			$oauth['oauth_signature_method'] 	= $this->_signatureMethod;
			$oauth['oauth_version'] 			= $this->_version;
			
			if ($url == $this->_accessTokenUrl){
				$oauth['oauth_verifier'] 		= $this->_getAccessVerifier();
			}
			/* echo $url . '<br>'. $_accessTokenUrl; */
			array_walk($oauth, array($this, '_encode_rfc3986'));
			
			if ( is_array($params) )
			{
				
				array_walk($params, array($this, '_walk_encode_rfc3986'));

			}
		
			$encodedParams = array_merge($oauth, (array)$params);
			
			ksort($encodedParams);
			
			$oauth['oauth_signature'] = $this->_encode_rfc3986($this->_generateSignature($method, $url, $encodedParams));

			
			$reorder_oauth=array();
			
			/* REORDER OAUTH TO TRY TO BETTER GET AUTHENTICATED */
			
			if (isset($oauth['oauth_callback'])){
				$reorder_oauth["oauth_callback"] = $oauth['oauth_callback'];
			}
			
			$reorder_oauth["oauth_consumer_key"] =$oauth['oauth_consumer_key'] ;
			$reorder_oauth["oauth_nonce"] =$oauth['oauth_nonce'] ;
			$reorder_oauth["oauth_signature"] =$oauth['oauth_signature'];
			$reorder_oauth["oauth_signature_method"] =$oauth['oauth_signature_method'] ; 
			$reorder_oauth["oauth_timestamp"] =$oauth['oauth_timestamp'] ; 
			$reorder_oauth["oauth_token"] =$oauth['oauth_token'] ;
			
			if ($url == $this->_accessTokenUrl){
				$reorder_oauth['oauth_verifier'] 		= $oauth['oauth_verifier'];
			}
			$reorder_oauth["oauth_version"] =$oauth['oauth_version'];	
			
			if ($url == $this->_requestTokenUrl){
			
				$reorder_oauth['oauth_callback'] = urlencode($callback);
			
				}
						
			return array('request' => $params, 'oauth' => $reorder_oauth);
		}
	
		private function _generateNonce()
		{
			return md5(uniqid(rand(), TRUE));
		}
		
		private function _walk_encode_rfc3986(&$string, $key)
		{
			$search = array('#', ',', '+', ':', ' ','~','!');
			$replace = array('%23', '%2C', '%2B', '%3A', '%20','%7E','%21');
			$string = str_replace($search, $replace, $string); 
       
     
		}
		
		private function _encode_rfc3986($string)
		{
			return str_replace( '%23', '#', str_replace('%20', ' ', str_replace('%7E', '~', rawurlencode(($string)))));
			
			}
		
		private function _generateSignature($method = null, $url = null, $params = null)
		{
			if( empty($method) || empty($url) ) return FALSE;
			
			// concatenating
			$concatenatedParams = '';
			
			foreach ($params as $k => $v)
			{
			
			if (strpos($url, 'search/tweets')  === false) 
				{
				   	$v = $this->_encode_rfc3986($v);
				}
			
			
				$concatenatedParams .= "{$k}={$v}&";
			}
			
			$concatenatedParams = $this->_encode_rfc3986(substr($concatenatedParams, 0, -1));

			// normalize url
			$normalizedUrl = $this->_encode_rfc3986($this->_normalizeUrl($url));
			$method = $this->_encode_rfc3986($method); // don't need this but why not?

			$signatureBaseString = "{$method}&{$normalizedUrl}&{$concatenatedParams}";

			
			;
			return $this->_signString($signatureBaseString);
		}
		
		private function _normalizeUrl($url = NULL)
		{ 
			$urlParts = parse_url($url);
			
			$scheme = strtolower($urlParts['scheme']);
			
			switch ( $scheme ){
			
				case 'http':
				$urlParts['port'] = 80;
				break;
				case 'https':
				$urlParts['port'] = 443;
				break;
				
			}
			if ( !isset($urlParts['port']) ) $urlParts['port'] = 80;

			
			$host = strtolower($urlParts['host']);
			$port = intval($urlParts['port']);

			$retval = "{$scheme}://{$host}";
			
			if ( $port > 0 && ( $scheme === 'http' && $port !== 80 ) || ( $scheme === 'https' && $port !== 443 ) )
			{
				$retval .= ":{$port}";
			}
			
			$retval .= $urlParts['path'];
			
			if ( !empty($urlParts['query']) )
			{
				$retval .= "?{$urlParts['query']}";
			}

			return $retval;
		}
		
		private function _signString($string)
		{
			$retval = FALSE;
			switch ( $this->_signatureMethod )
			{
				case 'HMAC-SHA1':
					$key = $this->_encode_rfc3986($this->_getConsumerSecret()) . '&' . $this->_encode_rfc3986($this->_getAccessSecret());
					$retval = base64_encode(hash_hmac('sha1', $string, $key, true));
				break;
			}

			return $retval;
		}

	}
