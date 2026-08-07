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


use EGroupware\Api;
use DateInterval;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use League\OAuth2\Server\Entities\ClientEntityInterface;
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

		if (!($client = $this->clientRepository->getClientEntity($clientIdentifier)))
		{
			return null;	// client does not (or no longer) exist
		}

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

			$token = $this->issueAccessToken($ttl, $client, (string)$this->user, $scopes);
		}
		if ($return_jwt === false)
		{
			return $token;
		}
		return $token->convertToJWT($this->privateKey, is_array($return_jwt) ? $return_jwt : [])->toString();
	}

	/**
	 * Parse and validate a JWT eg. issued by accessToken method
	 *
	 * We only validate expiration date and signature, not that the token is a (stored and not revoked) access-token.
	 *
	 * @param string $jwt
	 * @return ?UnencryptedToken null if token is expired or signature not valid, otherwise the token to e.g. retrieve a claim
	 */
	public function validateJWT($jwt)
	{
		$config = (new Keys())->jwtConfiguration();
		$token = $config->parser()->parse($jwt);

		if (!($token instanceof UnencryptedToken) || $this->isTokenExpired($token) || $this->isTokenUnverified($token))
		{
			return null;
		}
		return $token;
	}

	/**
	 * Validate an accessToken
	 *
	 * @param string $jwt
	 * @param string $min_lifetime ="PT5M" default 5minutes
	 * @param ClientEntityInterface|null &$client on return client-entity
	 * @return ?UnencryptedToken null if token is expired or signature not valid, otherwise the token to e.g. retrieve a claim
	 * @throws \League\OAuth2\Server\Exception\OAuthServerException
	 */
	public function validate($jwt, string $min_lifetime="PT5M", ?ClientEntityInterface &$client=null)
	{
		if (($token = $this->validateJWT($jwt)) &&
			// lcobucci/jwt 5.x's permittedFor() always stores "aud" as an array; we only ever
			// issue tokens for a single client
			($aud = $token->claims()->get('aud')) &&
			($client = $this->clientRepository->getClientEntity(is_array($aud) ? reset($aud) : $aud)) &&
			($account_id = Api\Accounts::getInstance()->name2id($token->claims()->get('sub'))) &&
			$this->accessTokenRepository->findToken($client, $account_id, $min_lifetime, $token->claims()->get('jti')))
		{
			return $token;
		}
		return null;
	}

	/**
	 * Checks whether the token is unverified.
	 *
	 * @param UnencryptedToken $token
	 *
	 * @return bool
	 */
	private function isTokenUnverified(UnencryptedToken $token)
	{
		$config = (new Keys())->jwtConfiguration();

		return !$config->validator()->validate($token, new SignedWith($config->signer(), $config->verificationKey()));
	}

	/**
	 * Ensure access token hasn't expired.
	 *
	 * @param UnencryptedToken $token
	 *
	 * @return bool
	 */
	private function isTokenExpired(UnencryptedToken $token)
	{
		$config = (new Keys())->jwtConfiguration();

		return !$config->validator()->validate($token, new StrictValidAt(SystemClock::fromUTC()));
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

		$client = $this->clientRepository->getClientEntity($clientIdentifier);
		$ttl = new DateInterval(empty($lifetime) ? $lifetime : Repositories\ClientRepository::getDefaultAuthCodeTTL());

		$token = $this->issueAuthCode($ttl, $client, (string)$this->user, $client->getRedirectUri(), $scopes);

		return $token->getIdentifier();
	}

	/**
	 * Required to extends AbstractGrant
	 *
	 * @return string
	 */
	function getIdentifier() : string
	{
		return '';
	}

 	/**
	 * Required to extends AbstractGrant
	 */
   public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ) : ResponseTypeInterface
	{
		unset($request, $responseType, $accessTokenTTL);
		throw new \LogicException(__CLASS__.' does not support '.__FUNCTION__);
	}
}
