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

use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

/**
 * Display UI to let user authorize a request
 */
class Authorize
{
	/**
	 * Request we need to autorize
	 *
	 * @var AuthorizationRequest
	 */
	protected $authRequest;

	public function __construct(AuthorizationRequest $authRequest)
	{
		$this->authRequest = $authRequest;
	}

	/**
	 * Display form to use to approve scopes given by client
	 *
	 * Displays an eT2 template and stores AuthorizationRequest object in session.
	 *
	 * @return boolean
	 */
	public function approve()
	{
		return true;
	}
}
