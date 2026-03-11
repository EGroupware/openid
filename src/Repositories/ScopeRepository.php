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
use League\OAuth2\Server\Entities\ScopeEntityInterface;
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
	 * Prefix for application scopes
	 */
	const APP_PREFIX = 'app-';

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
		// adding app-scopes
		foreach($GLOBALS['egw_info']['apps'] ?? [] as $app)
		{
			if ($app['status'] && $app['status'] != 3)  // enabled and not API
			{
				$scopes[self::APP_PREFIX.$app['name']] = [
					'id' => -$app['id'],
					'identifier' => self::APP_PREFIX.$app['name'],
					'description' => self::appScopeDescription($app['name']),
				];
			}
		}
		return $scopes;
	}

	protected static function appScopeDescription(string $app)
	{
		return lang('Application %1, allows to run that application', lang($app));
	}

	/**
	 * Return information about a scope.
	 *
	 * @param string $identifier The scope identifier
	 *
	 * @return ScopeEntityInterface
	 * @throws OAuthServerException
	 */
	public function getScopeEntityByIdentifier($identifier)
	{
		if (str_starts_with($identifier, self::APP_PREFIX) && isset($GLOBALS['egw_info']['apps'][$app=substr($identifier, strlen(self::APP_PREFIX))]))
		{
			$data = [
				'scope_id' => -$GLOBALS['egw_info']['apps'][$app]['id'],
				'scope_identifier' => self::APP_PREFIX . $app,
				'scope_description' => self::appScopeDescription($app),
			];
		}
		elseif (str_starts_with($identifier, self::APP_PREFIX) ||
			!($data = $this->db->select(self::TABLE, '*', ['scope_identifier' => $identifier],
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
	 * Return scopes specified by their id
	 *
	 * @param array|string $ids array or comma-separated string of scope id's
	 *
	 * @return ScopeEntityInterface[]
	 */
	public function getScopeEntitiesById($_ids)
	{
		if (!is_array($_ids))
		{
			$_ids = explode(',', (string)$_ids);
		}
		$scopes = [];
		if (($ids = array_filter($_ids, static fn($id) => $id > 0)))
		{
			foreach($this->db->select(self::TABLE, '*', [
				'scope_id' => $ids,
			], __LINE__, __FILE__, false, '', self::APP) as $data)
			{
				$scope = new ScopeEntity();
				$scope->setID($data['scope_id']);
				$scope->setIdentifier($data['scope_identifier']);
				$scope->setDescription($data['scope_description']);
				$scopes[] = $scope;
			}
		}
		if (($apps = array_filter($GLOBALS['egw_info']['apps'] ?? [], static fn($app) => in_array(-$app['id'], $_ids))))
		{
			foreach ($apps as $data)
			{
				$scope = new ScopeEntity();
				$scope->setID(-$data['id']);
				$scope->setIdentifier(self::APP_PREFIX.$data['name']);
				$scope->setDescription(self::appScopeDescription($data['name']));
				$scopes[] = $scope;
			}
		}
		return $scopes;
	}

    /**
     * Given a client, grant type and optional user identifier validate the set of scopes requested are valid and optionally
     * append additional scopes or remove requested scopes.
     *
     * @param ScopeEntityInterface[] $scopes
     * @param string                 $grantType
     * @param ClientEntityInterface  $clientEntity
     * @param null|string            $userIdentifier
     *
     * @return ScopeEntityInterface[]
     */
	public function finalizeScopes(
		array $scopes,
		$grantType,
		ClientEntityInterface $clientEntity,
		$userIdentifier = null
	) {
		unset($userIdentifier);	// not used, but required by function signature

		// check if grantType is allowed for the client
		if ($grantType && ($limitGrants = $clientEntity->getGrants()) &&
			!in_array($grantType, $limitGrants))
		{
			return [];
		}

		// check if scopes are allowed for the client
		if (($limitScopes = $clientEntity->getScopes()))
		{
			$scopes = array_filter($scopes, function($scope) use ($limitScopes)
			{
				return in_array($scope->getIdentifier(), $limitScopes);
			});
		}

		return $scopes;
	}

	/**
	 * Get available scopes as selectbox options for eT2
	 *
	 * @return array id => label
	 */
	public function selOptions()
	{
		static $scopes = null;

		if (!isset($scopes))
		{
			$scopes = [];
			foreach($this->getScopes() as $row)
			{
				if ($row['identifier'] === 'openid')
				{
					$row['identifier'] = 'OpenID ';	// hack to not translate to app-name
				}
				$scopes[(string)$row['id']] = [
					'label' => !str_starts_with($row['identifier'], self::APP_PREFIX) ? $row['identifier'] :
						lang('Application %1', lang(substr($row['identifier'], strlen(self::APP_PREFIX)))),
					'title' => $row['description'],
				];
			}
		}
		return $scopes;
	}

	/**
	 * Check given scopes are valid
	 *
	 * @param string|array $scopes multiple scope-ids or -identifiers
	 * @return array with integer scope_id => scope_identifier
	 * @throws Api\Exception\WrongParameter for invalid values in $scopes
	 */
	public function checkScopes($scopes)
	{
		$valid_scopes = array_map(function($s)
		{
			return $s['title'];
		}, $this->selOptions());

		$ids = [];
		foreach(is_array($scopes) ? $scopes : ($scopes ? explode(',', $scopes) : []) as $scope)
		{
			if (isset($valid_scopes[$scope]))
			{
				$ids[(int)$scope] = $valid_scopes[$scope];
			}
			elseif(($id = array_search($scope, $valid_scopes)) !== false)
			{
				$ids[(int)$id] = $scope;
			}
			else
			{
				throw new WrongParameter("Invalid scope '$scope'!");
			}
		}
		return $ids;
	}
}