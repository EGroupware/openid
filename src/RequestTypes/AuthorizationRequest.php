<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * Implement RFC7662 OAuth 2.0 Token Introspection
 * Until OAuth2 server pull request #925 is not merged:
 * @link https://github.com/thephpleague/oauth2-server/pull/925
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

namespace EGroupware\OpenID\RequestTypes;

use League\OAuth2\Server\RequestTypes;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use OpenIDConnectServer\IdTokenResponse;

/**
 * Class AuthorizationRequest
 *
 * Extended to persist response_type parameter
 *
 * @package EGroupware\OpenID\RequestTypes
 */
class AuthorizationRequest extends RequestTypes\AuthorizationRequest
{
	/**
	 * @var array
	 */
	protected $response_types;

	/**
	 * Check for a given response_type
	 *
	 * @param string $type
	 * @return bool
	 */
	public function needResponseType($type)
	{
		return in_array($type, $this->response_types);
	}

	/**
	 * @param string|array $response_types
	 */
	public function setResponseTypes($response_types)
	{
		$this->response_types = is_array($response_types) ? $response_types : explode(' ', $response_types);
	}

	/**
	 * @var string
	 */
	protected $nonce;

	/**
	 * @param string $nonce
	 */
	public function setNonce($nonce)
	{
		$this->nonce = $nonce;
	}

	/**
	 * @return string
	 */
	public function getNonce()
	{
		return $this->nonce;
	}

	/**
	 * @var IdTokenResponse
	 */
	protected $response;

	/**
	 * Set response object
	 *
	 * @param RedirectResponse $response
	 */
	public function setResponse(IdTokenResponse $response)
	{
		$this->response = $response;
	}

	/**
	 * Get response object
	 *
	 * @return IdTokenResponse
	 */
	public function getResponse()
	{
		return $this->response;
	}
}
