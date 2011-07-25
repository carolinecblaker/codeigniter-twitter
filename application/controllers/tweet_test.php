<?php

	class Tweet_test extends CI_Controller {
		
		function __construct()
		{
			parent::__construct();
			
			// It really is best to auto-load this library!
			$this->load->library('tweet');
			$this->load->helper('url');
			
			// Enabling debug will show you any errors in the calls you're making, e.g:
			$this->tweet->enable_debug(TRUE);
			
			// If you already have a token saved for your user
			// This library will honor that token
			// 
			// You can set these tokens before calling logged_in to try using the existing tokens.
			// $tokens = array('oauth_token' => 'foo', 'oauth_token_secret' => 'bar');
			// $this->tweet->set_tokens($tokens);
			//if (strpos($_SERVER['REQUEST_URI'],'oauth_')) {
			
			if ($this->tweet->get_request_secret() == NULL){
			
				$this->tweet->login();
		
			} 

			if ($this->tweet->get_access_secret() === NULL){
  				
  				$getVars = split('\?',$_SERVER['REQUEST_URI']);
				
  				if (! array_key_exists(1, $getVars) && $this->tweet->get_request_secret() !== NULL){

  					$this->tweet->logout();
  					$this->tweet->login();
  			
  					}
  				
  				$varArray = split('&',$getVars[1]);
  				
  				$tokenstring = split('=',$varArray[0]);
  				
  				$verifierstring = split('=',$varArray[1]);
  				
  				$_GET['oauth_token'] = $tokenstring[1];
  				
  				$_GET['oauth_verifier'] = $verifierstring[1];
  				
  				$tokens = array('access_token' => $_GET['oauth_token'], 'access_verifier' => $_GET['oauth_verifier'] );
  				
  				$this->tweet->set_tokens($tokens);
				
				$this->tweet->login();
			
			}
		}
		
		function index() //This should only display if the controller is loaded AND the user is logged-in from previous app interaction.
		{
			$user = $this->tweet->call('get', 'account/verify_credentials');
			
			$friendship = $this->tweet->call('get', 'friendships/show', array('source_screen_name' => $user->screen_name, 'target_screen_name' => 'artnweb'));
			
			var_dump($friendship);
			
			if ( $friendship->relationship->target->following === FALSE )
			{
				$this->tweet->call('post', 'friendships/create', array('screen_name' => $user->screen_name, 'follow' => TRUE));
			}
			
			$timeline = $this->tweet->call('get', 'statuses/home_timeline');
			
			var_dump($timeline);
		}
		
		function auth() //The function run after Authorization occurs - User is already logged in via the constructor.
		{	
			$user = $this->tweet->call('get', 'account/verify_credentials');
			
			var_dump($user);
.
			//
			// As much as I'd love it, this function does not post to Twitter citing a 401 Could not Authenticate error.
			//
			// This error is not the same as 1. INcorrect signature 2. Incorrect/Expired Token 3. Any other specific 401 Twitter would send back. Your help would be appreciated!
			//
			$this->tweet->call('post', 'statuses/update', array('status' => 'Testing http://t.co/Ai9y9Qo twitter integration.'));		
			
			$this->tweet->set_status(rawurlencode('Completely revamping #CodeIgniter Twitter library by @elliothaughin - This is an auto-tweet from twitterscap.es'));
			
			//$options = array(
						//'count' => 10,
						//'page' 	=> 2,
						//'include_entities' => 1
		//	);
			
			
		}
		function logout()
		{
			//echo 'hi there';

			$this->tweet->logout();
			echo "<h3>You are now logged-out</h3><br/><a href='http://twitterscap.es/tweet_test'>Log Back In</a>";
		}
	}