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

require_once __DIR__.'/../vendor/autoload.php';
use DateInterval;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Generate tokens (programaitic) for current user
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
		$this->authCodeRepository = new Repositories\AuthCodeRepository();
		$this->scopeRepository = new Repositories\ScopeRepository();
		$this->privateKey = (new Keys)->getPrivateKey();
	}

	/**
	 * Generate an access-token for current-user and given client
	 *
	 * @param string $clientIdentifier client-identifier
	 * @param string[] $scopeIdentifiers scope-identifiers
	 * @param string $lifetime ='DT1H' lifetime of token
	 * @return string access-token as (signed) JWT
	 */
	public function accessToken($clientIdentifier, array $scopeIdentifiers, $lifetime='PT1H')
	{
		$scopes = array_map(function($id)
		{
			return $this->scopeRepository->getScopeEntityByIdentifier($id);
		}, $scopeIdentifiers);

		$client = $this->clientRepository->getClientEntity($clientIdentifier, null, null, false);
		$ttl = new DateInterval($lifetime);

		$token = $this->issueAccessToken($ttl, $client, $this->user, $scopes);

		return (string)$token->convertToJWT($this->privateKey);
	}

	/**
	 * Generate an auth-code for current-user and given client
	 *
	 * @param string $clientIdentifier client-identifier
	 * @param string[] $scopeIdentifiers scope-identifiers
	 * @param string $lifetime ='DT10M' lifetime of token
	 * @return string access-token
	 */
	public function authCode($clientIdentifier, array $scopeIdentifiers, $lifetime='PT10M')
	{
		$scopes = array_map(function($id)
		{
			return $this->scopeRepository->getScopeEntityByIdentifier($id);
		}, $scopeIdentifiers);

		$client = $this->clientRepository->getClientEntity($clientIdentifier, null, null, false);
		$ttl = new DateInterval($lifetime);

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