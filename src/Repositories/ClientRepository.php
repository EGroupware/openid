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

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use EGroupware\OpenID\Entities\ClientEntity;
use EGroupware\Api;

class ClientRepository extends Base implements ClientRepositoryInterface
{
	/**
	 * Name of clients table
	 */
	const TABLE = 'egw_openid_clients';
	const CLIENT_GRANTS_TABLE = 'egw_openid_client_grants';
	const CLIENT_SCOPES_TABLE = 'egw_openid_client_scopes';

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
		$grants = 'SELECT '.$this->db->group_concat('grant_id').
			' FROM '.self::CLIENT_GRANTS_TABLE.
			' WHERE '.self::CLIENT_GRANTS_TABLE.'.client_id='.self::TABLE.'.client_id';

		$scopes = 'SELECT '.$this->db->group_concat('scope_identifier').
			' FROM '.self::CLIENT_SCOPES_TABLE.
			' JOIN '.ScopeRepository::TABLE.' ON '.ScopeRepository::TABLE.'.scope_id='.self::CLIENT_SCOPES_TABLE.'.scope_id'.
			' WHERE '.self::CLIENT_SCOPES_TABLE.'.client_id='.self::TABLE.'.client_id';

		$where = ['client_identifier' => $clientIdentifier];

		if (!empty($grantType))
		{
			$where[] = $this->db->expression(self::CLIENT_GRANTS_TABLE, ['grant_id' => GrantRepository::getGrantId($grantType)]);
			$join = 'JOIN '.self::CLIENT_GRANTS_TABLE.' ON '.self::CLIENT_GRANTS_TABLE.'.client_id='.self::TABLE.'.client_id';
		}

		if (!($data = $this->db->select(self::TABLE, "*,($grants) AS grants,($scopes) AS scopes",
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
			$data['grants'] = explode(',', $data['scopes']);
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

        return $client;
    }
}
