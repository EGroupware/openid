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
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 */

namespace EGroupware\OpenID\Entities;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class ClientEntity implements ClientEntityInterface
{
    use EntityTrait, ClientTrait, Traits\IdTrait;

    public function setName($name)
    {
        $this->name = $name;
    }

    public function getName()
    {
        return $this->name;
    }

    public function setRedirectUri($uri)
    {
        $this->redirectUri = $uri;
    }

    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

	protected $secretHash;

	public function getSecretHash()
	{
		return $this->secretHash;
	}

	public function setSecretHash($hash)
	{
		$this->secretHash = $hash;
	}

	public function setSecret($secret)
	{
		$this->secretHash = password_hash($secret, PASSWORD_BCRYPT);
	}

	/**
	 * @var array
	 */
	protected $scopes;

	/**
	 * Set supported scope identifiers
	 *
	 * @param ?array $scopes
	 */
	public function setScopes(?array $scopes=null)
	{
		$this->scopes = $scopes;
	}

	/**
	 * Get supported scope identifiers
	 *
	 * @return array|null null: all
	 */
	public function getScopes()
	{
		return $this->scopes;
	}

	/**
	 * @var array
	 */
	protected $grants;

	/**
	 * Set supported grant identifiers
	 *
	 * @param ?array $grants
	 */
	public function setGrants(?array $grants=null)
	{
		$this->grants = $grants;
	}

	/**
	 * Get supported grant ideentifiers
	 *
	 * @return array|null null: all
	 */
	public function getGrants()
	{
		return $this->grants;
	}

	/**
	 * TTL for access-tokens, to overwrite global default
	 *
	 * @var string
	 */
	protected $access_token_ttl;

	/**
	 * Set access-token TTL
	 *
	 * @param string|null $ttl null to use global default
	 */
	function setAccessTokenTTL($ttl)
	{
		$this->access_token_ttl = $ttl;
	}

	/**
	 * Get access-token TTL
	 *
	 * @return string|null null to use global default
	 */
	function getAccessTokenTTL()
	{
		return $this->access_token_ttl;
	}

	/**
	 * TTL for refresh-tokens, to overwrite global default
	 *
	 * @var string
	 */
	protected $refresh_token_ttl;

	/**
	 * Set refresh-token TTL
	 *
	 * @param string|null $ttl null to use global default
	 */
	function setRefreshTokenTTL($ttl)
	{
		$this->refresh_token_ttl = $ttl;
	}

	/**
	 * Get refresh-token TTL
	 *
	 * @return string|null null to use global default
	 */
	function getRefreshTokenTTL()
	{
		return $this->refresh_token_ttl;
	}

	/**
	 * @var string|null
	 */
	protected $app_name;

	/**
	 * Get application name, if managed as EGroupware app
	 *
	 * @return string|null
	 */
	function getApplicationName()
	{
		return $this->app_name;
	}

	/**
	 * Set application name, if managed as EGroupware app
	 *
	 * @param string|null $name
	 */
	function setApplicationName($name)
	{
		$this->app_name = $name;
	}

	/**
	 * Check if current user is allowed for this client
	 *
	 * If client is not managed as EGroupware App, all EGroupware users are allowed
	 *
	 * @return boolean
	 */
	function currentUserAllowed()
	{
		return !isset($this->app_name) || isset($GLOBALS['egw_info']['user']['apps'][$this->app_name]);
	}
}