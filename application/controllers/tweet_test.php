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
			// (In a db for example) - See line #37
			// 
			// You can set these tokens before calling logged_in to try using the existing tokens.
			// $tokens = array('oauth_token' => 'foo', 'oauth_token_secret' => 'bar');
			// $this->tweet->set_tokens($tokens);
			//if (strpos($_SERVER['REQUEST_URI'],'oauth_')) {
			
			
			if ($this->tweet->get_access_secret() == NULL){
			//echo "null!";
			if ( !$this->tweet->logged_in() )
			{
				// This is where the url will go to after auth.
				// ( Callback url )
				//echo '<h2> Processing as if not logged_in</h2>';
				$this->tweet->set_callback(site_url('tweet_test/auth'));
				
				// Send the user off for login!
				$this->tweet->login();
			}
  			$getVars = split('\?',$_SERVER['REQUEST_URI']);
  			$varArray = split('&',$getVars[1]);
  			$tokenstring = split('=',$varArray[0]);
  			$verifierstring = split('=',$varArray[1]);
  			$_GET['oauth_token'] = $tokenstring[1];
  			$_GET['oauth_verifier'] = $verifierstring[1];
  			//$oauth_token_secret = $verifierstring[1];
  			$tokens = array('oauth_token' => $_GET['oauth_token'], 'oauth_token_secret' => $_GET['oauth_verifier'] );
  			//echo 'Controller Tokens:';
  			//print_r($tokens);
			  //$this->tweet->set_tokens($tokens);

  			//
  			//log_message('info','Parsed the URL and $_GET should equal something now.');

		//	}
			//print_r($_GET);


			//exit;
			
			if ( !$this->tweet->logged_in() )
			{
				// This is where the url will go to after auth.
				// ( Callback url )
				///echo '<h2> Processing as if not logged_in</h2>';
				$this->tweet->set_callback(site_url('tweet_test/auth'));
				
				// Send the user off for login!
				$this->tweet->login();
			}
			else
			{
			//echo '<h2> You are logged_in</h2>';
				// You can get the tokens for the active logged in user:
				$tokens = $this->tweet->get_tokens();
	
				// 
				// These can be saved in a db alongside a user record
				// if you already have your own auth system.
			}
			}
		}
		
		function index()
		{
			echo 'hi there';
			$this->session->unset_userdata('user_data');
			echo "data unset";
		}
		
		function auth()
		{
			//$tokens = $this->tweet->get_tokens();
			//$this->tweet->set_tokens($tokens);
			
			
			// $user = $this->tweet->call('get', 'account/verify_credentiaaaaaaaaals');
			// 
			// Will throw an error with a stacktrace.
			
			$user = $this->tweet->call('get', 'account/verify_credentials');
			var_dump($user);
			
			$friendship = $this->tweet->call('get', 'friendships/show', array('source_screen_name' => $user->screen_name, 'target_screen_name' => 'artnweb'));
			var_dump($friendship);
			
			if ( $friendship->relationship->target->following === FALSE )
			{
				$this->tweet->call('post', 'friendships/create', array('screen_name' => $user->screen_name, 'follow' => TRUE));
			}
			
			$this->tweet->set_status(rawurlencode('Completely revamping #CodeIgniter Twitter library by @elliothaughin - http://bit.ly/grHmua - This is an auto-tweet from http://twitterscap.es'));
			
			$options = array(
						'count' => 10,
						'page' 	=> 2,
						'include_entities' => 1
			);
			
			$timeline = $this->tweet->call('get', 'statuses/home_timeline');
			
			var_dump($timeline);
		}
	}