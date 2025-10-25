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
 * @link https://github.com/thephpleague/oauth2-server
 */

namespace EGroupware\OpenID;

// suppress deprecation errors, until we're able to updated steverhoades/oauth2-openid-connect-server and specially lcobucci/jwt
error_reporting(E_ALL & ~E_DEPRECATED);

use DateInterval;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Keychain;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\ValidationData;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Generate tokens (programmatic) for current user
 */
class Token extends AbstractGrant
{
	/**
	 * Current active user
	 *
	 * @var int
	 */
	protected $user;

	function __construct()
	{
		$this->user = $GLOBALS['egw_info']['user']['account_id'];

		$this->clientRepository = new Repositories\ClientRepository();
		$this->accessTokenRepository = new Repositories\AccessTokenRepository();
		$this->refreshTokenRepository = new Repositories\RefreshTokenRepository();
		$this->authCodeRepository = new Repositories\AuthCodeRepository();
		$this->scopeRepository = new Repositories\ScopeRepository();
		$this->privateKey = (new Keys)->getPrivateKey();
	}

	/**
	 * Find or generate an access-token for current-user and given client
	 *
	 * Returns NULL if user has not authorized client: no valid access- or refresh-token exists
	 *
	 * @param string $clientIdentifier client-identifier
	 * @param string[] $scopeIdentifiers scope-identifiers
	 * @param string $min_lifetime =null min. lifetime for existing token, null: create new token with default TTL
	 * @param boolean $require_refresh_token =true true: require a refresh token to exist (user authorized before), false: do no check refresh-token
	 * @param string $lifetime =null lifetime of new token or null to use client default
	 * @param boolean|array $return_jwt =true true: return JWT, false: return AccessTokenEntity
	 * 	or array with name => value pairs with extra claims added to the JWT
	 * @return string|AccessTokenEntity access-token or (signed) JWT
	 */
	public function accessToken($clientIdentifier, array $scopeIdentifiers, $min_lifetime=null,
		$require_refresh_token=true, $lifetime=null, $return_jwt=true)
	{
		$scopes = array_map(function($id)
		{
			return $this->scopeRepository->getScopeEntityByIdentifier($id);
		}, $scopeIdentifiers);

		$client = $this->clientRepository->getClientEntity($clientIdentifier, null, null, false);

		if (!empty($min_lifetime))
		{
			$token = $this->accessTokenRepository->findToken($client, $this->user, $min_lifetime);
		}
		// if no valid token is found
		if (!isset($token))
		{
			if ($require_refresh_token && !$this->refreshTokenRepository->findToken($client, $this->user, $min_lifetime))
			{
				return NULL;	// user has not yes authorized client
			}
			// ToDo: do a propper refresh using RefreshTokenGrant->respondToAccessTokenRequest()
			// for now we just create a new access-token
			if (empty($lifetime) && empty($lifetime = $client->getAccessTokenTTL()))
			{
				$lifetime = Repositories\ClientRepository::getDefaultAccessTokenTTL();
			}
			$ttl = new DateInterval($lifetime);

			$token = $this->issueAccessToken($ttl, $client, $this->user, $scopes);
		}
		return $return_jwt === false ? $token :
			(string)$token->convertToJWT($this->privateKey, is_array($return_jwt) ? $return_jwt : []);
	}

	/**
	 * Parse and validate a JWT eg. issued by accessToken method
	 *
	 * We only validate expiration date and signature, not that the token is a (stored and not revoked) access-token.
	 *
	 * @param string $jwt
	 * @return ?Token null if token is expired or signature not valid, otherwise the token to e.g. retrive a claim
	 */
	public function validateJWT($jwt)
	{
		$token = (new Parser())->parse($jwt);

		if ($this->isTokenExpired($token) || $this->isTokenUnverified($token))
		{
			return null;
		}
		return $token;
	}

	/**
	 * Checks whether the token is unverified.
	 *
	 * @param Token $token
	 *
	 * @return bool
	 */
	private function isTokenUnverified(\Lcobucci\JWT\Token $token)
	{
		$keychain = new Keychain();

		$privateKey = new Keys();
		$key = $keychain->getPrivateKey(
			$privateKey->getPrivateKey()->getKeyPath(),
			$privateKey->getPrivateKey()->getPassPhrase()
		);

		return $token->verify(new Sha256(), $key->getContent()) === false;
	}

	/**
	 * Ensure access token hasn't expired.
	 *
	 * @param Token $token
	 *
	 * @return bool
	 */
	private function isTokenExpired(\Lcobucci\JWT\Token $token)
	{
		$data = new ValidationData(time());

		return !$token->validate($data);
	}

	/**
	 * Generate an auth-code for current-user and given client
	 *
	 * @param string $clientIdentifier client-identifier
	 * @param string[] $scopeIdentifiers scope-identifiers
	 * @param string $lifetime =null lifetime of auth-code, null: use default
	 * @return string access-token
	 */
	public function authCode($clientIdentifier, array $scopeIdentifiers, $lifetime=null)
	{
		$scopes = array_map(function($id)
		{
			return $this->scopeRepository->getScopeEntityByIdentifier($id);
		}, $scopeIdentifiers);

		$client = $this->clientRepository->getClientEntity($clientIdentifier, null, null, false);
		$ttl = new DateInterval(empty($lifetime) ? $lifetime : Repositories\ClientRepository::getDefaultAuthCodeTTL());

		$token = $this->issueAuthCode($ttl, $client, $this->user, $client->getRedirectUri(), $scopes);

		return $token->getIdentifier();
	}

	/**
	 * Required to extends AbstractGrant
	 *
	 * @return string
	 */
	function getIdentifier()
	{
		return null;
	}

 	/**
	 * Required to extends AbstractGrant
	 *
	 * @return string
	 */
   public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    )
	{
		unset($request, $responseType, $accessTokenTTL);
	}
}