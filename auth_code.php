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
use League\OAuth2\Server\Grant\AuthCodeGrant;
use EGroupware\OpenID\Repositories\AccessTokenRepository;
use EGroupware\OpenID\Repositories\AuthCodeRepository;
use EGroupware\OpenID\Repositories\ClientRepository;
use EGroupware\OpenID\Repositories\RefreshTokenRepository;
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

$GLOBALS['egw_info'] = array(
	'flags' => array(
		// only /authorize needs a session, /access_token does not
		'currentapp'	=> $_SERVER['PATH_INFO'] === '/authorize' ? 'api' : 'login',
		'nonavbar'		=> True,
		'noheader'      => True,
		'autocreate_session_callback' => Authorize::class.'::anon_session',
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
		$authCodeRepository = new AuthCodeRepository();
		$refreshTokenRepository = new RefreshTokenRepository();

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

		// Enable the authentication code grant on the server with a token TTL of 1 hour
		$server->enableGrantType(
			new AuthCodeGrant(
				$authCodeRepository,
				$refreshTokenRepository,
				new \DateInterval('PT10M')
			),
			new \DateInterval('PT1H')
		);

		return $server;
	},
]);

$app->get('/authorize', function (ServerRequestInterface $request, ResponseInterface $response) use ($app)
{
	/* @var \League\OAuth2\Server\AuthorizationServer $server */
	$server = $app->getContainer()->get(AuthorizationServer::class);

	try {
		$auth = new Authorize('/openid/'.basename(__FILE__).'/authorize');
		// validate does NOT return, before user has approved or denied the request!
		$authRequest = $auth->validate($server, $request);

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

$app->post('/access_token', function (ServerRequestInterface $request, ResponseInterface $response) use ($app)
{
	/* @var \League\OAuth2\Server\AuthorizationServer $server */
	$server = $app->getContainer()->get(AuthorizationServer::class);

	try {
		return $server->respondToAccessTokenRequest($request, $response);
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
