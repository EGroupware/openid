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

// until #925 is merged: use League\OAuth2\Server\AuthorizationServer;
use EGroupware\OpenId\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use EGroupware\OpenId\Grant\AuthCodeGrant;
use EGroupware\OpenId\Grant\ClientCredentialsGrant;
use EGroupware\OpenId\Grant\ImplicitGrant;
use EGroupware\OpenId\Grant\PasswordGrant;
use EGroupware\OpenId\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Middleware\ResourceServerMiddleware;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;
use EGroupware\OpenID\ResponseTypes\IdTokenResponse;
use EGroupware\OpenID\Middleware\LegacyMiddlewareAdapter;
use EGroupware\OpenID\Repositories\AccessTokenRepository;
use EGroupware\OpenID\Repositories\AuthCodeRepository;
use EGroupware\OpenID\Repositories\ClientRepository;
use EGroupware\OpenID\Repositories\RefreshTokenRepository;
use EGroupware\OpenID\Repositories\UserRepository;
use EGroupware\OpenID\Repositories\IdentityRepository;
use EGroupware\OpenID\Repositories\ScopeRepository;
use EGroupware\OpenID\Entities\UserEntity;
use EGroupware\OpenID\Keys;
use EGroupware\OpenID\Authorize;
use EGroupware\OpenID\Log;
use EGroupware\OpenID\ClaimExtractor;

$GLOBALS['egw_info'] = array(
	'flags' => array(
		// only /authorize needs a session, /access_token does not
		'currentapp'	=> $_SERVER['PATH_INFO'] === '/authorize' ? 'api' : 'login',
		'nonavbar'		=> True,
		'noheader'      => True,
		'autocreate_session_callback' => Authorize::class.'::anon_session',
));
include('../header.inc.php');

/**
 * Build the AuthorizationServer, with all grants enabled and client-specific token TTLs
 *
 * No DI container is used (Slim 4 doesn't require one for an app this size): these are plain
 * local variables, built once, captured by the route closures below.
 */
function createAuthorizationServer() : AuthorizationServer
{
	// Init our repositories
	$clientRepository = new ClientRepository();
	$scopeRepository = new ScopeRepository();
	$accessTokenRepository = new AccessTokenRepository();
	$authCodeRepository = new AuthCodeRepository();
	$refreshTokenRepository = new RefreshTokenRepository();
	$keys = new Keys();

	// OpenID Connect Response Type
	$responseType = new IdTokenResponse(new IdentityRepository(), new ClaimExtractor());

	// Setup the authorization server
	$server = new AuthorizationServer(
		$clientRepository,
		$accessTokenRepository,
		$scopeRepository,
		$keys->getPrivateKey(),
		$keys->getEncryptionKey(),
		$responseType
	);

	// Enable the client credentials grant on the server
	$server->enableGrantType(
		new ClientCredentialsGrant(),
		new \DateInterval(ClientRepository::getDefaultAccessTokenTTL())
	);

	// Enable the implicit grant on the server with a token TTL of 1 hour
	$server->enableGrantType(
		new ImplicitGrant(
			$authCodeRepository,
			new \DateInterval(ClientRepository::getDefaultAuthCodeTTL()),
			new \DateInterval(ClientRepository::getDefaultAccessTokenTTL())
		)
	);

	// Enable the authentication code grant on the server
	$server->enableGrantType(
		new AuthCodeGrant(
			$authCodeRepository,
			$refreshTokenRepository,
			new \DateInterval(ClientRepository::getDefaultAuthCodeTTL())
		),
		new \DateInterval(ClientRepository::getDefaultAccessTokenTTL())
	);

	// Enable the password grant on the server with a token TTL of 1 hour
	$pwGrant = new PasswordGrant(
		new UserRepository(),           // instance of UserRepositoryInterface
		$refreshTokenRepository
	);
	$pwGrant->setRefreshTokenTTL(new \DateInterval(ClientRepository::getDefaultRefreshTokenTTL()));

	$server->enableGrantType(
		$pwGrant,
		new \DateInterval(ClientRepository::getDefaultAccessTokenTTL())
	);

	// Enable the refresh token grant on the server
	$refreshGrant = new RefreshTokenGrant($refreshTokenRepository);
	$refreshGrant->setRefreshTokenTTL(new \DateInterval(ClientRepository::getDefaultRefreshTokenTTL()));

	$server->enableGrantType(
		$refreshGrant,
		new \DateInterval(ClientRepository::getDefaultAccessTokenTTL())
	);

	return $server;
}

$server = createAuthorizationServer();
$resourceServer = new ResourceServer(
	new AccessTokenRepository(),
	(new Keys())->getPublicKey()
);

$app = AppFactory::create();
// Slim 4 no longer auto-detects the base path from SCRIPT_NAME like Slim 3 did
$app->setBasePath($_SERVER['SCRIPT_NAME']);

$app->get('/authorize', function (ServerRequestInterface $request, ResponseInterface $response) use ($server)
{
	try {
		$auth = new Authorize('/openid/'.basename(__FILE__).'/authorize');
		// validate does NOT return, before user has approved or denied the request!
		$authRequest = $auth->validate($server, $request);

		// Return the HTTP redirect response
		return $server->completeAuthorizationRequest($authRequest, $response);
	}
	catch (OAuthServerException $exception) {
		return $exception->generateHttpResponse($response);
	}
	catch (\Exception $exception) {
		_egw_log_exception($exception);
		$response->getBody()->write($exception->getMessage());

		return $response->withStatus(500);
	}
});

$app->post('/access_token', function (ServerRequestInterface $request, ResponseInterface $response) use ($server)
{
	try {
		return $server->respondToAccessTokenRequest($request, $response);
	}
	catch (OAuthServerException $exception) {
		return $exception->generateHttpResponse($response);
	}
	catch (\Exception $exception) {
		_egw_log_exception($exception);
		$response->getBody()->write($exception->getMessage());

		return $response->withStatus(500);
	}
});

$app->post(
    '/introspect',
    function (ServerRequestInterface $request, ResponseInterface $response) use ($server) {
         try {
            // Validate the given introspect request
            $server->validateIntrospectionRequest($request);
             // Try to respond to the introspection request
            return $server->respondToIntrospectionRequest($request, $response);
        }
		catch (OAuthServerException $exception) {
             // All instances of OAuthServerException can be converted to a PSR-7 response
            return $exception->generateHttpResponse($response);
        }
		catch (\Exception $exception) {
			_egw_log_exception($exception);
            $response->getBody()->write($exception->getMessage());
            return $response->withStatus(500);
        }
    }
);

$app->get('/userinfo', function (ServerRequestInterface $request, ResponseInterface $response)
{
	try {
		$account_id = $request->getAttribute('oauth_user_id');
		$user = new UserEntity($account_id);
		$params = ['sub' => $user->getIdentifier()];
		$claimExtractor = new ClaimExtractor();
		$params += $claimExtractor->extract(
			$request->getAttribute('oauth_scopes', []),
			$user->getClaims()
		);
		$response->getBody()->write(json_encode($params));
		return $response
			->withStatus(200)
			->withHeader('pragma', 'no-cache')
			->withHeader('cache-control', 'no-store')
			->withHeader('content-type', 'application/json; charset=UTF-8');
	}
	catch (\Exception $exception) {
		_egw_log_exception($exception);
		$response->getBody()->write($exception->getMessage());

		return $response->withStatus(500);
	}
})->add(new LegacyMiddlewareAdapter(new ResourceServerMiddleware($resourceServer), $app->getResponseFactory()));

$app->get('/jwks', function (ServerRequestInterface $request, ResponseInterface $response)
{
	try
	{
		$keys = new Keys();

		$response->getBody()->write(json_encode(['keys' => [$keys->getJWK()]]));

		return $response
			->withStatus(200)
			->withHeader('content-type', 'application/json; charset=UTF-8');
	}
	catch (\Exception $exception) {
		_egw_log_exception($exception);
		$response->getBody()->write($exception->getMessage());

		return $response->withStatus(500);
	}
});

// Slim does NOT detect Authorization header with Apache not writing it to $_SERVER['HTTP_AUTHORIZATION']
if (function_exists('apache_request_headers') && !isset($_SERVER['HTTP_AUTHORIZATION']) &&
	($headers = apache_request_headers()) && isset($headers['Authorization']))
{
	$_SERVER['HTTP_AUTHORIZATION'] = $headers['Authorization'];
}

$app->addRoutingMiddleware();
$app->addBodyParsingMiddleware();

// Add our PSR-15 middleware logger
$formatter = new Log\HttpFormatter();
// create a full request log in "$files/openid/request.log"
$app->add(new Log\Middleware($formatter, $formatter, new Log\Logger('openid')));

$app->addErrorMiddleware(true, true, true);

$app->run();
