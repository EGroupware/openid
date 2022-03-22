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

use EGroupware\OpenID\Entities\ScopeEntity;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use EGroupware\OpenID\Entities\ClientEntity;
use EGroupware\Api;

class ClientRepository extends Api\Storage\Base implements ClientRepositoryInterface
{
	/**
	 * Application name
	 */
	const APP = 'openid';

	/**
	 * Name of clients table
	 */
	const TABLE = 'egw_openid_clients';
	const CLIENT_GRANTS_TABLE = 'egw_openid_client_grants';
	const CLIENT_SCOPES_TABLE = 'egw_openid_client_scopes';

	/**
	 * SQL to generate comma-separated grants/scopes
	 *
	 * @var string
	 */
	protected $grants_sql;
	protected $scopes_sql;
	protected $scope_identifiers_sql;

	/**
	 * Constructor
	 */
	function __construct()
	{
		parent::__construct(self::APP, self::TABLE, null, '', true);

		$this->grants_sql = 'SELECT '.$this->db->group_concat('grant_id').
			' FROM '.self::CLIENT_GRANTS_TABLE.
			' WHERE '.self::CLIENT_GRANTS_TABLE.'.client_id='.self::TABLE.'.client_id';

		$this->scopes_sql = 'SELECT '.$this->db->group_concat('scope_id').
			' FROM '.self::CLIENT_SCOPES_TABLE.
			' WHERE '.self::CLIENT_SCOPES_TABLE.'.client_id='.self::TABLE.'.client_id';

		$this->scope_identifiers_sql = 'SELECT '.$this->db->group_concat('scope_identifier').
			' FROM '.self::CLIENT_SCOPES_TABLE.
			' JOIN '.ScopeRepository::TABLE.' ON '.ScopeRepository::TABLE.'.scope_id='.self::CLIENT_SCOPES_TABLE.'.scope_id'.
			' WHERE '.self::CLIENT_SCOPES_TABLE.'.client_id='.self::TABLE.'.client_id';
	}

    /**
     * Get a client.
     *
     * @param string      $clientIdentifier   The client's identifier
     * @param null|string $grantType          The grant type used (if sent)
     * @param null|string $clientSecret       The client's secret (if sent)
     * @param bool        $mustValidateSecret If true the client must attempt to validate the secret if the client
     *                                        is confidential
     *
     * @return ClientEntityInterface
     */
    public function getClientEntity($clientIdentifier, $grantType = null, $clientSecret = null, $mustValidateSecret = true)
    {
		$where = ['client_identifier' => $clientIdentifier, 'client_status' => true];

		if (!empty($grantType))
		{
			$where[] = $this->db->expression(self::CLIENT_GRANTS_TABLE, ['grant_id' => GrantRepository::getGrantId($grantType)]);
			$join = 'JOIN '.self::CLIENT_GRANTS_TABLE.' ON '.self::CLIENT_GRANTS_TABLE.'.client_id='.self::TABLE.'.client_id';
		}

		if (!($data = $this->db->select(self::TABLE, "*,($this->grants_sql) AS grants,($this->scope_identifiers_sql) AS scopes",
			$where, __LINE__, __FILE__, false, '', self::APP, null, $join)->fetch()))
		{
			throw OAuthServerException::invalidClient();
		}
		$data = Api\Db::strip_array_keys($data, 'client_');

		if (!empty($data['grants']))
		{
			$data['grants'] = array_map(GrantRepository::class.'::getGrantById', explode(',', $data['grants']));
		}
		if (!empty($data['scopes']))
		{
			$data['scopes'] = explode(',', $data['scopes']);
		}

        if (
            $mustValidateSecret === true
            && !empty($data['secret']) === true	// only store secrets for confidential clients
            && password_verify($clientSecret, $data['secret']) === false
        ) {
            return;
        }

        $client = new ClientEntity();
		$client->setID($data['id']);
        $client->setIdentifier($data['identifier']);
        $client->setName($data['name']);
        $client->setRedirectUri($data['redirect_uri']);
		$client->setScopes($data['scopes']);
		$client->setGrants($data['grants']);
		$client->setAccessTokenTTL($data['access_token_ttl']);
		$client->setRefreshTokenTTL($data['refresh_token_ttl']);
		$client->setApplicationName($data['app_name'] ?:
			// always consider rocketchat implicit as app managed by egroupware (to not require explicit user consent!)
			(strpos($data['redirect_uri'], '/rocketchat/') !== false ? 'rocketchat' : null));

        return $client;
    }

	/**
	 * Persists a client to permanent storage
	 *
	 * @param ClientEntity $clientEntity
	 *
	 * @throws UniqueTokenIdentifierConstraintViolationException
	 */
	public function persistNewClient(ClientEntity $clientEntity)
	{
		//error_log(__METHOD__."(".array2string($clientEntity).")");

		try {
			$this->db->insert(self::TABLE, [
				'client_identifier' => $clientEntity->getIdentifier(),
				'client_secret' => $clientEntity->getSecretHash(),
				'client_name' => $clientEntity->getName(),
				'client_redirect_uri' => $clientEntity->getRedirectUri(),
				'client_access_token_ttl' => $clientEntity->getAccessTokenTTL(),
				'client_refresh_token_ttl' => $clientEntity->getRefreshTokenTTL(),
				'client_created' => time(),
				'app_name' => $clientEntity->getApplicationName(),
			], false, __LINE__, __FILE__, self::APP);

			$clientEntity->setID($this->db->get_last_insert_id(self::TABLE, 'client_id'));

			foreach($clientEntity->getScopes() as $scope)
			{
				$this->db->insert(self::CLIENT_SCOPES_TABLE, [
					'client_id' => $clientEntity->getID(),
					'scope_id' => is_a($scope, ScopeEntity::class) ? $scope->getID() : $scope,
				], false, __LINE__, __FILE__, self::APP);
			}

			foreach($clientEntity->getGrants() as $grant)
			{
				$this->db->insert(self::CLIENT_GRANTS_TABLE, [
					'client_id' => $clientEntity->getID(),
					'grant_id' => $grant > 0 ? $grant : GrantRepository::getGrantId($grant),
				], false, __LINE__, __FILE__, self::APP);
			}
		}
		catch(Api\Db\Exception\NotUnique $ex) {
			unset($ex);
			throw UniqueTokenIdentifierConstraintViolationException::create();
		}
	}

	/**
	 * Default refresh-token TTL
	 *
	 * @return string
	 */
	static function getDefaultRefreshTokenTTL()
	{
		return 'P1M';
	}

	/**
	 * Default access-token TTL
	 *
	 * @return string
	 */
	static function getDefaultAccessTokenTTL()
	{
		return 'PT1H';
	}

	/**
	 * Default auth-code TTL
	 *
	 * @return string
	 */
	static function getDefaultAuthCodeTTL()
	{
		return 'PT10M';
	}

	/**
	 * Changes the data from work-format to the db-format
	 *
	 * Reimplemented to hash passwords (client_secret)
	 *
	 * @param array $data =null if given works on that array and returns result, else works on internal data-array
	 * @return array
	 */
	function data2db($data=null)
	{
		if (($intern = !is_array($data)))
		{
			$data =& $this->data;
		}
		if (!empty($data['client_secret']))
		{
			$data['client_secret'] = password_hash($data['client_secret'], PASSWORD_BCRYPT);
		}
		else
		{
			unset($data['client_secret']);
		}
		return parent::data2db($intern ? null : $data);	// important to use null, if $intern!
	}

	/**
	 * Changes the data from the db-format to your work-format
	 *
	 * Reimplemented to explode comma-separated grants and scopes.
	 *
	 * @param array $data =null if given works on that array and returns result, else works on internal data-array
	 * @return array
	 */
	function db2data($data=null)
	{
		if (($intern = !is_array($data)))
		{
			$data =& $this->data;
		}
		// explode comma-separated grants and scopes
		foreach(['client_grants', 'client_scopes'] as $name)
		{
			if (isset($data[$name]))
			{
				$data[$name] = explode(',', $data[$name]);
			}
		}
		return parent::db2data($intern ? null : $data);	// important to use null, if $intern!
	}

	/**
	 * Save grant-ids for given client
	 *
	 * @param int $client_id
	 * @param array $grants integer grant-ids
	 */
	public function saveGrants($client_id, array $grants)
	{
		if ($client_id != $this->data['client_id'])
		{
			$this->read($client_id);
		}
		// add new grants
		foreach(array_diff($grants, (array)$this->data['client_grants']) as $grant_id)
		{
			$this->db->insert(self::CLIENT_GRANTS_TABLE, [
				'client_id' => $client_id,
				'grant_id' => $grant_id,
			], false, __LINE__, __FILE__, self::APP);
		}
		// remove no longer allowed grants
		if (($remove = array_diff((array)$this->data['client_grants'], $grants)))
		{
			$this->db->delete(self::CLIENT_GRANTS_TABLE, [
				'client_id' => $client_id,
				'grant_id' => $remove,
			], __LINE__, __FILE__, self::APP);
		}
		$this->data['client_grants'] = $grants;
	}

	/**
	 * Save scope-ids for given client
	 *
	 * @param int $client_id
	 * @param array $scopes =null integer scope-ids
	 */
	public function saveScopes($client_id, array $scopes=null)
	{
		if ($client_id != $this->data['client_id'])
		{
			$this->read($client_id);
		}
		// add new grants
		foreach(array_diff((array)$scopes, (array)$this->data['client_scopes']) as $scope_id)
		{
			$this->db->insert(self::CLIENT_SCOPES_TABLE, [
				'client_id' => $client_id,
				'scope_id' => $scope_id,
			], false, __LINE__, __FILE__, self::APP);
		}
		// remove no longer allowed grants
		if (($remove = array_diff((array)$this->data['client_scopes'], (array)$scopes)))
		{
			$this->db->delete(self::CLIENT_SCOPES_TABLE, [
				'client_id' => $client_id,
				'scope_id' => $remove,
			], __LINE__, __FILE__, self::APP);
		}
		$this->data['client_scopes'] = $scopes;
	}

	/**
	 * Reads row matched by key and puts all cols in the data array
	 *
	 * Reimplemented to get comma-separated client_(scopes|grants) and allow to filter by them.
	 *
	 * @param array $keys array with keys in form internalName => value, may be a scalar value if only one key
	 * @param string|array $extra_cols ='' string or array of strings to be added to the SELECT, eg. "count(*) as num"
	 * @param string $join ='' sql to do a join, added as is after the table-name, eg. ", table2 WHERE x=y" or
	 * @return array|boolean data if row could be retrived else False
	 */
	function read($keys, $extra_cols='', $join='')
	{
		$this->addGrantsScopes($extra_cols);

		return parent::read(is_array($keys) || empty($keys) ? $keys :
			[(is_numeric($keys) ? 'client_id' : 'client_identifier') => $keys],
			$extra_cols, $join);
	}

	/**
	 * Searches db for rows matching searchcriteria
	 *
	 * Reimplemented to get comma-separated client_(scopes|grants) and allow to filter by them.
	 *
	 * @param array|string $criteria array of key and data cols, OR string with search pattern (incl. * or ? as wildcards)
	 * @param boolean|string|array $only_keys =true True returns only keys, False returns all cols. or
	 *	comma seperated list or array of columns to return
	 * @param string $order_by ='' fieldnames + {ASC|DESC} separated by colons ',', can also contain a GROUP BY (if it contains ORDER BY)
	 * @param string|array $extra_cols ='' string or array of strings to be added to the SELECT, eg. "count(*) as num"
	 * @param string $wildcard ='' appended befor and after each criteria
	 * @param boolean $empty =false False=empty criteria are ignored in query, True=empty have to be empty in row
	 * @param string $op ='AND' defaults to 'AND', can be set to 'OR' too, then criteria's are OR'ed together
	 * @param mixed $start =false if != false, return only maxmatch rows begining with start, or array($start,$num), or 'UNION' for a part of a union query
	 * @param array $filter =null if set (!=null) col-data pairs, to be and-ed (!) into the query without wildcards
	 * @param string $join ='' sql to do a join, added as is after the table-name, eg. "JOIN table2 ON x=y" or
	 *	"LEFT JOIN table2 ON (x=y AND z=o)", Note: there's no quoting done on $join, you are responsible for it!!!
	 * @param boolean $need_full_no_count =false If true an unlimited query is run to determine the total number of rows, default false
	 * @return array|NULL array of matching rows (the row is an array of the cols) or NULL
	 */
	function &search($criteria, $only_keys=True, $order_by='', $extra_cols='', $wildcard='', $empty=False, $op='AND', $start=false, $filter=null, $join='', $need_full_no_count=false)
	{
		$this->addGrantsScopes($extra_cols);

		if (!empty($filter['client_scopes']))
		{
			$join .= ' LEFT JOIN '.self::CLIENT_SCOPES_TABLE.' ON '.self::CLIENT_SCOPES_TABLE.'.client_id='.self::TABLE.'.client_id';
			$filter[] = $this->db->expression(self::CLIENT_SCOPES_TABLE, '(', ['scope_id' => $filter['client_scopes']], ' OR scope_id IS NULL)');
		}
		if (!empty($filter['client_grants']))
		{
			$join .= ' JOIN '.self::CLIENT_GRANTS_TABLE.' ON '.self::CLIENT_GRANTS_TABLE.'.client_id='.self::TABLE.'.client_id';
			$filter[] = $this->db->expression(self::CLIENT_GRANTS_TABLE, ['grant_id' => $filter['client_grants']]);
		}
		unset($filter['client_grants'], $filter['client_scopes']);

		return parent::search($criteria, $only_keys, $order_by, $extra_cols, $wildcard, $empty, $op, $start, $filter, $join, $need_full_no_count);
	}

	/**
	 * Add comma-separated client_(grants|scopes) column
	 *
	 * @param string|array& $extra_cols on return always array
	 */
	protected function addGrantsScopes(&$extra_cols)
	{
		if ($extra_cols)
		{
			$extra_cols = is_array($extra_cols) ? $extra_cols : implode(',', $extra_cols);
		}
		else
		{
			$extra_cols = [];
		}
		$extra_cols[] = "($this->grants_sql) AS client_grants";
		$extra_cols[] = "($this->scopes_sql) AS client_scopes";
	}
}