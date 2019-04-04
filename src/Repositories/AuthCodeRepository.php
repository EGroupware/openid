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

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use EGroupware\OpenID\Entities\AuthCodeEntity;

/**
 * Auth code storage interface.
 */
class AuthCodeRepository extends Base implements AuthCodeRepositoryInterface
{
	/**
	 * Name of auth-code table
	 */
	const TABLE = 'egw_openid_auth_codes';
	const AUTH_CODE_SCOPES_TABLE = 'egw_openid_auth_code_scopes';

    /**
     * Persists a new auth code to permanent storage.
     *
     * @param AuthCodeEntityInterface $authCodeEntity
     *
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity)
    {
		//error_log(__METHOD__."(".array2string($authCodeEntity).")");

		try {
			$this->db->insert(self::TABLE, [
				'auth_code_identifier' => $authCodeEntity->getIdentifier(),
				'client_id' => $authCodeEntity->getClient()->getID(),
				'account_id' => $authCodeEntity->getUserIdentifier(),
				'auth_code_redirect_uri' => $authCodeEntity->getRedirectUri(),
				'auth_code_expiration' => $authCodeEntity->getExpiryDateTime(),
				'auth_code_created' => time(),
			], false, __LINE__, __FILE__, self::APP);

			$authCodeEntity->setID($this->db->get_last_insert_id(self::TABLE, 'auth_code_id'));

			foreach($authCodeEntity->getScopes() as $scope)
			{
				$this->db->insert(self::AUTH_CODE_SCOPES_TABLE, [
					'auth_code_id' => $authCodeEntity->getID(),
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
     * Revoke an auth code.
     *
     * @param string $codeId
     */
    public function revokeAuthCode($codeId)
    {
		$this->db->update(self::TABLE, [
			'auth_code_revoked' => true,
		], [
			'auth_code_identifier' => $codeId,
		], __LINE__, __FILE__, self::APP);
    }

    /**
     * Check if the auth code has been revoked.
     *
     * @param string $codeId
     *
     * @return bool Return true if this code has been revoked
     */
    public function isAuthCodeRevoked($codeId)
    {
		$revoked = $this->db->select(self::TABLE, 'auth_code_revoked', [
			'auth_code_identifier' => $codeId,
		], __LINE__, __FILE__, false, '', self::APP)->fetchColumn();

		return $revoked === false || $this->db->from_bool($revoked);
    }

    /**
     * Creates a new AuthCode
     *
     * @return AuthCodeEntityInterface
     */
    public function getNewAuthCode()
    {
        return new AuthCodeEntity();
    }
}
