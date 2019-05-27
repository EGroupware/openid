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
	 * Numerical values for available grants
	 */
	const CLIENT_CREDENTIALS = 1;
	const PASSWORD = 2;
	const IMPLICIT = 3;
	const AUTHORIZATION_CODE = 4;
	const REFRESH_TOKEN = 5;

	/**
	 * Ids to store in database for grants
	 *
	 * @var array
	 */
	protected static $grants_ids = [
		'client_credentials' => self::CLIENT_CREDENTIALS,
		'password' => self::PASSWORD,
		'implicit' => self::IMPLICIT,
		'authorization_code' => self::AUTHORIZATION_CODE,
		'refresh_token' => self::REFRESH_TOKEN,
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

	/**
	 * Get available grants as selectbox options for eT2
	 *
	 * @param boolean $short =false true: remove "Grant" from all labels
	 * @return array
	 */
	public static function selOptions($short=false)
	{
		static $grants = null;

		if (!isset($grants))
		{
			$grants = [];
			foreach(self::$grants_ids as $identifier => $id)
			{
				$grants[$id] = self::$grants_descriptions[$identifier];
			}
		}
		return $short ? str_replace(' Grant', '', $grants) : $grants;
	}

	/**
	 * Check given grants are valid
	 *
	 * @param string|array $grants multiple grant-ids or -identifiers
	 * @return array with integer grant-id => identifier
	 * @throws Api\Exception\WrongParameter for invalid values in $grants
	 */
	public function checkGrants($grants)
	{
		$ids = [];
		foreach(is_array($grants) ? $grants : explode(',', $grants) as $grant)
		{
			if (isset(self::$grants_ids[$grant]))
			{
				$ids[self::$grants_ids[$grant]] = $grant;
			}
			elseif(($identifier = array_search($grant, self::$grants_ids)) !== false)
			{
				$ids[(int)$grant] = $identifier;
			}
			else
			{
				throw new WrongParameter("Invalid grant '$grant'!");
			}
		}
		return $ids;
	}
}