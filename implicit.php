<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 *
 * Based on the following MIT Licensed packages:
 * @link https://github.com/steverhoades/oauth2-openid-connect-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @link https://github.com/thephpleague/oauth2-server
 */

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ImplicitGrant;
use EGroupware\OpenID\Entities\UserEntity;
use EGroupware\OpenID\Repositories\AccessTokenRepository;
use EGroupware\OpenID\Repositories\ClientRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\App;
use Zend\Diactoros\Stream;
use OpenIDConnectServer\IdTokenResponse;
use EGroupware\OpenID\Repositories\IdentityRepository;
use EGroupware\OpenID\Repositories\ScopeRepository;
use OpenIDConnectServer\ClaimExtractor;
use EGroupware\OpenID\Key;
use EGroupware\OpenID\Authorize;
use EGroupware\Api;

/**
 * Check if we have a session
 */
$no_session = false;

$GLOBALS['egw_info'] = array(
	'flags' => array(
		'currentapp'	=> 'api',
		'nonavbar'		=> True,
		'noheader'      => True,
		'autocreate_session_callback' => function(&$anon_account) use (&$no_session)
		{
			$anon_account = null;

			// we dont have a session, but want to continue
			$no_session = !empty($_COOKIE['last_loginid']) ? $_COOKIE['last_loginid'] : true;

			// create session without checking auth: create(..., false, false)
			return $GLOBALS['egw']->session->create('anonymous@'.$GLOBALS['egw_info']['user']['domain'],
				'', 'text', false, false);
		}
));
include('../header.inc.php');

include __DIR__ . '/vendor/autoload.php';

$app = new App([
    'settings'    => [
        'displayErrorDetails' => true,
    ],
    AuthorizationServer::class => function () {
        // Init our repositories
        $clientRepository = new ClientRepository();
        $scopeRepository = new ScopeRepository();
        $accessTokenRepository = new AccessTokenRepository();

        $privateKeyPath = Key::getPrivate();

        // OpenID Connect Response Type
        $responseType = new IdTokenResponse(new IdentityRepository(), new ClaimExtractor());

        // Setup the authorization server
        $server = new AuthorizationServer(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKeyPath,
            'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen',
            $responseType
        );

        // Enable the implicit grant on the server with a token TTL of 1 hour
        $server->enableGrantType(new ImplicitGrant(new \DateInterval('PT1H')));

        return $server;
    },
]);

$app->get('/authorize', function (ServerRequestInterface $request, ResponseInterface $response) use ($app, $no_session)
{
    /* @var \League\OAuth2\Server\AuthorizationServer $server */
    $server = $app->getContainer()->get(AuthorizationServer::class);

    try {
		// check if we have stored authRequest, restore it
		if (!$no_session && ($ar = Api\Cache::getSession('openid', 'authRequest')))
		{
			$authRequest = unserialize($ar);
		}
		else
		{
			// Validate the HTTP request and return an AuthorizationRequest object.
			// The auth request object can be serialized into a user's session
			$authRequest = $server->validateAuthorizationRequest($request);

			// if we have no user-session --> redirect to login
			if ($no_session)
			{
				// we need to explicit serialize $authRequest, as our autoloader is not yet loaded at session_start!
				Api\Cache::setSession('openid', 'authRequest', serialize($authRequest));
				// if we had a "last_loginid" cookie, before creating the anon session, restore it
				if ($no_session !== true)
				{
					Api\Session::egw_setcookie('last_loginid', $no_session , Api\DateTime::to('+2weeks', 'ts'));
				}
				Api\Framework::redirect_link('/login.php', [
					'phpgw_forward' => '/openid/'.basename(__FILE__).'/authorize?cd=no',
					'cd' => lang('Login to authorize %1', $authRequest->getClient()->getName())
				]);
			}
		}

		if ($authRequest->isAuthorizationApproved() === false)
		{
			// Once the user has logged in set the user on the AuthorizationRequest
			$authRequest->setUser(new UserEntity($GLOBALS['egw_info']['user']['account_id']));

			// ToDo: show user page with requested permissions, so he can approve or deny
			$auth = new Authorize($authRequest, '/openid/'.basename(__FILE__).'/authorize?cd=no');
			$auth->approve();	// does NOT return
		}
		// remove it for the next request
		Api\Cache::unsetSession('openid', 'authRequest');

		// Return the HTTP redirect response
        return $server->completeAuthorizationRequest($authRequest, $response);
    }
	catch (OAuthServerException $exception)
	{
        return $exception->generateHttpResponse($response);
    }
	catch (\Exception $exception)
	{
        $body = new Stream('php://temp', 'r+');
        $body->write($exception->getMessage());

        return $response->withStatus(500)->withBody($body);
    }
});

$app->run();
