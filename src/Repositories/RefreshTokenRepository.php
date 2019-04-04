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

/**
 * Refresh token storage interface.
 */
class RefreshTokenRepository extends Base implements RefreshTokenRepositoryInterface
{
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
				'client_id' => $refreshTokenEntity->getClient()->getID(),
				'account_id' => $refreshTokenEntity->getUserIdentifier(),
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
}
