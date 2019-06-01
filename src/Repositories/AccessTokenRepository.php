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
class AccessTokenRepository extends Base implements AccessTokenRepositoryInterface
{
	/**
	 * Table name
	 */
	const TABLE = 'egw_openid_access_tokens';
	const TOKEN_SCOPES_TABLE = 'egw_openid_access_token_scopes';

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
	 * @param string $tokenId
	 */
	public function revokeAccessToken($tokenId)
	{
		$this->db->update(self::TABLE, [
			'access_token_revoked' => true,
		], [
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

		return $accessToken;
	}

	/**
	 * Find a non-revoked access-token for a given client and user with given minimum lifetime
	 *
	 * @param ClientEntity $clientEntity
	 * @param UserEntity|int $userIdentifier
	 * @param string $min_lifetime =null minimum lifetime to return existing token
	 * @return AccessTokenEntity|null null if no (matching) token found
	 */
	public function findToken(ClientEntity $clientEntity, $userIdentifier, $min_lifetime)
	{
		$min_expiration = new \DateTime('now');
		$min_expiration->add(new \DateInterval($min_lifetime));

		$data = $this->db->select(self::TABLE, '*', [
			'client_id' => $clientEntity->getID(),
			'account_id' => is_a($userIdentifier, UserEntity::class) ? $userIdentifier->getID() : $userIdentifier,
			'access_token_revoked' => false,
			'access_token_expiration >= '.$this->db->quote($min_expiration, 'timestamp'),
		], __LINE__, __FILE__, 0, 'ORDER BY access_token_expiration DESC', self::APP, 1)->fetch();

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
}
