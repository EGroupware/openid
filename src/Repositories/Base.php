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

namespace EGroupware\OpenID\Repositories;

use EGroupware\Api;

/**
 * Base class for all OpenID repositories / storage objects
 */
class Base
{
	/**
	 * Application name
	 */
	const APP = 'openid';

	/**
	 * Reference to global Db object
	 *
	 * @var Api\Db
	 */
	protected $db;

	public function __construct()
	{
		$this->db = $GLOBALS['egw']->db;
	}
}