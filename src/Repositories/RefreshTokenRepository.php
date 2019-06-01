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
	public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity)
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
	 *
	 * @param string $tokenId
	 */
	public function revokeRefreshToken($tokenId)
	{
		$this->db->update(self::TABLE, [
			'refresh_token_revoked' => true,
		], [
			'refresh_token_identifier' => $tokenId,
		], __LINE__, __FILE__, self::APP);
	}

	/**
	 * Check if the refresh token has been revoked.
	 *
	 * @param string $tokenId
	 *
	 * @return bool Return true if this token has been revoked
	 */
	public function isRefreshTokenRevoked($tokenId)
	{
		$revoked = $this->db->select(self::TABLE, 'refresh_token_revoked', [
			'refresh_token_identifier' => $tokenId,
		], __LINE__, __FILE__, false, '', self::APP)->fetchColumn();

		return $revoked === false || $this->db->from_bool($revoked);
	}

	/**
	 * Creates a new refresh token
	 *
	 * @return RefreshTokenEntityInterface
	 */
	public function getNewRefreshToken()
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

		$data = $this->db->select(self::TABLE, '*', [
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
			$token->setExpiryDateTime(new \DateTime($data['refresh_token_expiration']));
			$access_token = new AccessTokenEntity();
			$access_token->setClient($clientEntity);
			$access_token->setId($data['access_token_id']);
			$access_token->setIdentifier($data['access_token_identifier']);
			$access_token->setExpiryDateTime(new \DateTime($data['access_token_expiration']));
			$access_token->setUserIdentifier((int)$data['account_id']);
			$token->setAccessToken($access_token);
		}
		return $token;
	}
}
