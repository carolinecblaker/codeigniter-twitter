CodeIgniter-Twitter
=============

A complete library giving you twitter oauth authentication and api access.

[Elliot Haughin - CodeIgniter Twitter Library - Documentation](http://www.haughin.com/code/twitter/)


EDIT: May 17, 2011 by .carolinecblaker. http://carolineblaker.com

Hi Folks,

I've spent many hours conforming this to oAuth's new specs. I no longer have time to develop it, so I'm releasing it so that hopefully someone with a fresh set of eyes, and perhaps better programming skills, can fix this puppy up.

The summary of the changes:

controllers/tweet_test.php : Added (and kept, from some other forks) notification text that dumps vars. Known bugs: Refreshing will nullify your login.

libraries/tweet.php : 

     Under consideration of these docs:

      http://dev.twitter.com/pages/auth

I have added several functions that track extra pieces of oAuth data now required for login. The controller and this library together now complete a login perfectly. This library cannot yet post tweets as there are elements of the post that need to be added to the signature - which is where I left off.

I no longer have time to work on this (which is kind of a good thing) - so I hope that you are able to use it and perfect it.

