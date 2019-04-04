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

namespace EGroupware\OpenID\Entities;

/**
 * Base class for all OpenID entities
 */
class Base
{
	/**
	 *
	 * @var int
	 */
	protected $id;

	/**
	 * Set nummeric ID
	 *
	 * @parm $id int
	 */
	public function setID($id)
	{
		$this->id = $id;
	}

	/**
	 * Get nummeric ID
	 *
	 * @return int
	 */
	public function getID()
	{
		return $this->id;
	}
}