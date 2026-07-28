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

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use EGroupware\OpenID\Entities\RefreshTokenEntity;
use EGroupware\OpenID\Entities\AccessTokenEntity;
use EGroupware\OpenID\Entities\ClientEntity;
use EGroupware\OpenID\Entities\UserEntity;

/**
 * Refresh token storage interface.
 */
class RefreshTokenRepository extends Base implements RefreshTokenRepositoryInterface
{
	/**
	 * Name of auth-code table
	 */
	const TABLE = 'egw_openid_refresh_tokens';

	/**
	 * Create a new refresh token_name.
	 *
	 * @param RefreshTokenEntityInterface $refreshTokenEntity
	 *
	 * @throws UniqueTokenIdentifierConstraintViolationException
	 */
	public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity) : void
	{
		//error_log(__METHOD__."(".array2string($refreshTokenEntity).")");

		try {
			$this->db->insert(self::TABLE, [
				'refresh_token_identifier' => $refreshTokenEntity->getIdentifier(),
				'access_token_id' => $refreshTokenEntity->getAccessToken()->getID(),
				'refresh_token_expiration' => $refreshTokenEntity->getExpiryDateTime(),
				'refresh_token_created' => time(),
			], false, __LINE__, __FILE__, self::APP);

			$refreshTokenEntity->setID($this->db->get_last_insert_id(self::TABLE, 'refresh_token_id'));
		}
		catch(Api\Db\Exception\NotUnique $ex) {
			unset($ex);
			throw UniqueTokenIdentifierConstraintViolationException::create();
		}
	}

	/**
	 * Revoke the refresh token.
	 */
	public function revokeRefreshToken(string $tokenId) : void
	{
		$this->revokeRefreshTokenByQuery(['refresh_token_identifier' => $tokenId]);
	}

	/**
	 * Revoke refresh token(s) matching an arbitrary query, eg. ['access_token_id' => $id]
	 *
	 * Used by User.php to revoke a token selected in the "manage your tokens" UI, where we only
	 * have the numeric access_token_id, not the (unencrypted, unavailable) token identifier.
	 *
	 * @param array $query column => value pairs
	 */
	public function revokeRefreshTokenByQuery(array $query) : void
	{
		$this->db->update(self::TABLE, [
			'refresh_token_revoked' => true,
		], $query, __LINE__, __FILE__, self::APP);
	}

	/**
	 * Check if the refresh token has been revoked.
	 *
	 * @return bool Return true if this token has been revoked
	 */
	public function isRefreshTokenRevoked(string $tokenId) : bool
	{
		$revoked = $this->db->select(self::TABLE, 'refresh_token_revoked', [
			'refresh_token_identifier' => $tokenId,
		], __LINE__, __FILE__, false, '', self::APP)->fetchColumn();

		return $revoked === false || $this->db->from_bool($revoked);
	}

	/**
	 * Creates a new refresh token
	 */
	public function getNewRefreshToken() : ?RefreshTokenEntityInterface
	{
		return new RefreshTokenEntity();
	}

	/**
	 * Find a non-revoked access-token for a given client and user with given minimum lifetime
	 *
	 * @param ClientEntity $clientEntity
	 * @param UserEntity|int $userIdentifier
	 * @param string $min_lifetime ='PT1H' minimum lifetime to return existing token
	 * @return AccessTokenEntity|null null if no (matching) token found
	 */
	public function findToken(ClientEntity $clientEntity, $userIdentifier, $min_lifetime='PT1H')
	{
		$min_expiration = new \DateTime('now');
		$min_expiration->add(new \DateInterval($min_lifetime));
		$access_token_repo = new AccessTokenRepository();

		$data = $this->db->select(self::TABLE, "*,($access_token_repo->scopes_sql) AS access_token_scopes", [
			'refresh_token_revoked' => false,
			'refresh_token_expiration >= '.$this->db->quote($min_expiration, 'timestamp'),
			$this->db->expression(AccessTokenRepository::TABLE, [
				'client_id' => $clientEntity->getID(),
				'account_id' => is_a($userIdentifier, UserEntity::class) ? $userIdentifier->getID() : $userIdentifier,
				'access_token_revoked' => false,
			]),
		], __LINE__, __FILE__, 0, 'ORDER BY refresh_token_expiration DESC', self::APP, 1,
		' JOIN '.AccessTokenRepository::TABLE.' ON '.self::TABLE.'.access_token_id='.
			AccessTokenRepository::TABLE.'.access_token_id')->fetch();

		if ($data)
		{
			$token = new RefreshTokenEntity();
			$token->setId($data['refresh_token_id']);
			$token->setIdentifier($data['refresh_token_identifier']);
			$token->setExpiryDateTime(new \DateTimeImmutable($data['refresh_token_expiration']));
			$access_token = new AccessTokenEntity();
			$access_token->setClient($clientEntity);
			$access_token->setId($data['access_token_id']);
			$access_token->setIdentifier($data['access_token_identifier']);
			$access_token->setExpiryDateTime(new \DateTimeImmutable($data['access_token_expiration']));
			$access_token->setUserIdentifier((string)$data['account_id']);
			if (!empty($data['access_token_scopes']))
			{
				try {
					$scopeRepo = new ScopeRepository();
					foreach($scopeRepo->getScopeEntitiesById($data['access_token_scopes']) as $scope)
					{
						$access_token->addScope($scope);
					}
				}
				catch (Api\Exception\WrongParameter $ex) {
					// access-token contains an invalid (eg. deleted) scope --> return no scopes
					_egw_log_exception($ex);
				}
			}
			$token->setAccessToken($access_token);
		}
		return $token;
	}
}
