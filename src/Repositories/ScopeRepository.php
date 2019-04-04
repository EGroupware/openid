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

namespace EGroupware\OpenID\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use EGroupware\OpenID\Entities\ScopeEntity;
use EGroupware\Api;

class ScopeRepository extends Base implements ScopeRepositoryInterface
{
	/**
	 * Name of scopes table
	 */
	const TABLE = 'egw_openid_scopes';

	/**
	 * Get available scopes
	 *
	 * @return array identifier => ['description'=>'...', ...]
	 */
	public function getScopes()
	{
		$scopes = [];
		foreach($this->db->select(self::TABLE, '*', false,
			__LINE__, __FILE__, false, '', self::APP) as $row)
		{
			$scopes[$row['scope_identifier']] = Api\Db::strip_array_keys($row, 'scope_');
		}
		return $scopes;
	}

	/**
	 * Return information about a scope.
	 *
	 * @param string $identifier The scope identifier
	 *
	 * @return ScopeEntityInterface
	 */
	public function getScopeEntityByIdentifier($identifier)
	{
		if (!($data = $this->db->select(self::TABLE, '*', ['scope_identifier' => $identifier],
			__LINE__, __FILE__, false, '', self::APP)->fetch()))
		{
			throw OAuthServerException::invalidScope($identifier);
		}

		$scope = new ScopeEntity();
		$scope->setID($data['scope_id']);
		$scope->setIdentifier($data['scope_identifier']);
		$scope->setDescription($data['scope_description']);

		return $scope;
	}

	/**
	 * {@inheritdoc}
	 */
	public function finalizeScopes(
		array $scopes,
		$grantType,
		ClientEntityInterface $clientEntity,
		$userIdentifier = null
	) {
		/* Example of programatically modifying the final scope of the access token
		if ((int) $userIdentifier === 1) {
			$scope = new ScopeEntity();
			$scope->setIdentifier('email');
			$scope->setDescription(self::$scopes[$scopeIdentifier]['description']);
			$scopes[] = $scope;
		}*/

		return $scopes;
	}
}
