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

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use EGroupware\OpenID\Entities\AccessTokenEntity;
use EGroupware\OpenID\Entities\UserEntity;
use EGroupware\OpenID\Entities\ClientEntity;
use EGroupware\Api;

/**
 * Access token storage interface.
 */
class AccessTokenRepository extends Api\Storage\Base implements AccessTokenRepositoryInterface
{
	const APP = 'openid';

	/**
	 * Table name
	 */
	const TABLE = 'egw_openid_access_tokens';
	const TOKEN_SCOPES_TABLE = 'egw_openid_access_token_scopes';

	/**
	 * SQL to generate comma-separated scopes
	 *
	 * @var string
	 */
	public $scopes_sql;

	/**
	 * Constructor
	 */
	function __construct()
	{
		parent::__construct(self::APP, self::TABLE, null, '', true);

		$this->scopes_sql = 'SELECT '.$this->db->group_concat('scope_id').
			' FROM '.self::TOKEN_SCOPES_TABLE.
			' WHERE '.self::TOKEN_SCOPES_TABLE.'.access_token_id='.self::TABLE.'.access_token_id';
	}

	/**
	 * Persists a new access token to permanent storage.
	 *
	 * @param AccessTokenEntityInterface $accessTokenEntity
	 *
	 * @throws UniqueTokenIdentifierConstraintViolationException
	 */
	public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity)
	{
		//error_log(__METHOD__."(".array2string($accessTokenEntity).")");

		try {
			$userEntity = new UserEntity($accessTokenEntity->getUserIdentifier());

			$this->db->insert(self::TABLE, [
				'access_token_identifier' => $accessTokenEntity->getIdentifier(),
				'client_id' => $accessTokenEntity->getClient()->getID(),
				'account_id' => $userEntity->getID(),
				'access_token_expiration' => $accessTokenEntity->getExpiryDateTime(),
				'access_token_created' => time(),
				'access_token_user_agent' => $accessTokenEntity->getUserAgent(),
				'access_token_ip' => $accessTokenEntity->getIP(),
			], false, __LINE__, __FILE__, self::APP);

			$accessTokenEntity->setID($this->db->get_last_insert_id(self::TABLE, 'access_token_id'));

			foreach($accessTokenEntity->getScopes() as $scope)
			{
				$this->db->insert(self::TOKEN_SCOPES_TABLE, [
					'access_token_id' => $accessTokenEntity->getID(),
					'scope_id' => $scope->getID(),
				], false, __LINE__, __FILE__, self::APP);
			}
		}
		catch(Api\Db\Exception\NotUnique $ex) {
			unset($ex);
			throw UniqueTokenIdentifierConstraintViolationException::create();
		}
	}

	/**
	 * Revoke an access token.
	 *
	 * @param string|array $tokenId token identifier or array with query
	 */
	public function revokeAccessToken($tokenId)
	{
		$this->db->update(self::TABLE, [
			'access_token_revoked' => true,
		], is_array($tokenId) ? $tokenId : [
			'access_token_identifier' => $tokenId,
		], __LINE__, __FILE__, self::APP);
	}

	/**
	 * Check if the access token has been revoked.
	 *
	 * @param string $tokenId
	 *
	 * @return bool Return true if this token has been revoked
	 */
	public function isAccessTokenRevoked($tokenId)
	{
		$revoked = $this->db->select(self::TABLE, 'access_token_revoked', [
			'access_token_identifier' => $tokenId,
		], __LINE__, __FILE__, false, '', self::APP)->fetchColumn();

		return $revoked === false || $this->db->from_bool($revoked);
	}

	/**
	 * Create a new access token
	 *
	 * @param ClientEntityInterface  $clientEntity
	 * @param ScopeEntityInterface[] $scopes
	 * @param mixed                  $userIdentifier
	 *
	 * @return AccessTokenEntityInterface
	 */
	public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null)
	{
		$accessToken = new AccessTokenEntity();
		$accessToken->setClient($clientEntity);
		foreach ($scopes as $scope) {
			$accessToken->addScope($scope);
		}
		$accessToken->setUserIdentifier($userIdentifier);
		$accessToken->setUserAgent();
		$accessToken->setIP();

		return $accessToken;
	}

	/**
	 * Find a non-revoked access-token for a given client and user with given minimum lifetime
	 *
	 * @param ClientEntity $clientEntity
	 * @param UserEntity|int $userIdentifier
	 * @param string $min_lifetime minimum lifetime to return existing token
	 * @param string $identifier =null token-identifier
	 * @return AccessTokenEntity|null null if no (matching) token found
	 */
	public function findToken(ClientEntity $clientEntity, $userIdentifier, $min_lifetime, $identifier=null)
	{
		$min_expiration = new \DateTime('now');
		$min_expiration->add(new \DateInterval($min_lifetime));

		$data = $this->db->select(self::TABLE, '*', [
			'client_id' => $clientEntity->getID(),
			'access_token_revoked' => false,
			'access_token_expiration >= '.$this->db->quote($min_expiration, 'timestamp'),
		]+($identifier ? ['access_token_identifier' => $identifier] : [])+(isset($userIdentifier)?[
			'account_id' => is_a($userIdentifier, UserEntity::class) ? $userIdentifier->getID() : $userIdentifier,
		] : []), __LINE__, __FILE__, 0, 'ORDER BY access_token_expiration DESC', self::APP, 1)->fetch();

		if ($data)
		{
			$token = new AccessTokenEntity();
			$token->setClient($clientEntity);
			$token->setId($data['access_token_id']);
			$token->setIdentifier($data['access_token_identifier']);
			$token->setExpiryDateTime(new \DateTime($data['access_token_expiration']));
			$token->setUserIdentifier((int)$data['account_id']);
		}
		return $token;
	}

	/**
	 * Searches db for rows matching searchcriteria
	 *
	 * Reimplemented to get comma-separated access_token_scopes and allow to filter by them.
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
		// by default, query only own tokens
		if (!isset($filter['account_id']))
		{
			$filter['account_id'] = $GLOBALS['egw_info']['user']['account_id'];
		}

		// optimize slow MariaDB 10.6 query, by first querying the id's and then everything for just these ids
		if ($start && is_array($start) && count($filter) === 1 && preg_match('/^[a-z0-9_]+( ASC| DESC)?$/i', $order_by))
		{
			[$offset, $num_rows] = $start;
			$filter['access_token_id'] = [];
			foreach($this->db->select(self::TABLE, 'SQL_CALC_FOUND_ROWS access_token_id', [
				'account_id' => $filter['account_id'],
			], __LINE__, __FILE__, $offset, 'ORDER BY '.$order_by, self::APP, $num_rows) as $row)
			{
				$filter['access_token_id'][] = $row['access_token_id'];
			}
			$ret = $this->search($criteria, $only_keys, $order_by, $extra_cols, $wildcard, $empty, $op, false, $filter, $join, $need_full_no_count);
			$this->total = $this->db->select($this->table_name, 'COUNT(*)', [
				'account_id' => $filter['account_id'],
			],__LINE__,__FILE__,false,'', $this->app, 0, $join)->fetchColumn();
			return $ret;
		}

		if ($extra_cols)
		{
			$extra_cols = is_array($extra_cols) ? $extra_cols : implode(',', $extra_cols);
		}
		else
		{
			$extra_cols = [];
		}
		$extra_cols[] = "($this->scopes_sql) AS access_token_scopes";

		if ($join === '')
		{
			// join clients to get client name and status
			$join .= ' LEFT JOIN '.ClientRepository::TABLE.' ON '.ClientRepository::TABLE.'.client_id='.self::TABLE.'.client_id';
			$extra_cols[] = ClientRepository::TABLE.'.client_name AS client_name';
			$extra_cols[] = ClientRepository::TABLE.'.client_status AS client_status';

			// join auth-codes to get real user-agent and ip
			// egw_openid_auth_codes has no foreign key to issued access-token nor the other way arround
			// --> use auth_code of same client and user revoked at the time access_code was created (+/-1sec)
			$join .= ' LEFT JOIN '.AuthCodeRepository::TABLE.' ON '.AuthCodeRepository::TABLE.'.client_id='.self::TABLE.'.client_id'.
				' AND '.AuthCodeRepository::TABLE.'.account_id='.self::TABLE.'.account_id'.
				' AND ABS('.$this->db->unix_timestamp(AuthCodeRepository::TABLE.'.auth_code_updated').'-'.
					$this->db->unix_timestamp(self::TABLE.'.access_token_created').')<=1'.
				' AND '.AuthCodeRepository::TABLE.'.auth_code_revoked='.$this->db->quote(true, 'boolean');
			$extra_cols[] = AuthCodeRepository::TABLE.'.auth_code_ip AS auth_code_ip';
			$extra_cols[] = AuthCodeRepository::TABLE.'.auth_code_user_agent AS auth_code_user_agent';

			// join refresh-token to get it's expiration
			$join .= ' LEFT JOIN '.RefreshTokenRepository::TABLE.' ON '.RefreshTokenRepository::TABLE.'.access_token_id='.self::TABLE.'.access_token_id';
			$extra_cols[] = RefreshTokenRepository::TABLE.'.refresh_token_expiration AS refresh_token_expiration';

			if ($only_keys === false || $only_keys === '*')
			{
				$only_keys = self::TABLE.'.*';
			}
		}

		if (!empty($filter['access_token_scopes']))
		{
			$join .= ' JOIN '.self::TOKEN_SCOPES_TABLE.' ON '.self::TOKEN_SCOPES_TABLE.'.access_token_id='.self::TABLE.'.access_token_id';
			$filter[] = $this->db->expression(self::TOKEN_SCOPES_TABLE, ['scope_id' => $filter['access_token_scopes']]);
		}
		if (!empty($filter['client_status']))
		{
			$filter[] = $this->db->expression(ClientRepository::TABLE, ['client_status' => $filter['client_status']]);
		}
		unset($filter['access_token_scopes'], $filter['client_status']);

		return parent::search($criteria, $only_keys, $order_by, $extra_cols, $wildcard, $empty, $op, $start, $filter, $join, $need_full_no_count);
	}
}