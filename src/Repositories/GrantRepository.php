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

/**
 * Mapping grant identifiers to database-ids and descriptions
 *
 * Not worth putting in the database, as we have only these 5 grants ...
 */
class GrantRepository
{
	/**
	 * Ids to store in database for grants
	 */
	protected static $grants_ids = [
		'client_credentials' => 1,
		'password' => 2,
		'implicit' => 3,
		'authorization_code' => 4,
		'refresh_token' => 5,
	];
	/**
	 * Description for grants
	 *
	 * @var array
	 */
	protected static $grants_descriptions = [
		'client_credentials' => 'Client Credentials Grant',
		'password' => 'Password Grant',
		'implicit' => 'Implicit Grant',
		'authorization_code' => 'Authorization Code Grant',
		'refresh_token' => 'Refresh Token Grant',
	];

	static function getGrantById($id)
	{
		return array_search($id, self::$grants_ids);
	}

	static function getGrantId($identifier)
	{
		return self::$grants_ids[$identifier];
	}

	static function getGrantDescription($identifer)
	{
		return self::$grants_descriptions[$identifer];
	}

	public static function getGrantDescriptions()
	{
		return self::$grants_descriptions;
	}
}