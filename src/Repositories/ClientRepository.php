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
		unset($grantType);	// currently now used, but required but interface

		if (!($data = $this->db->select(self::TABLE, '*', ['client_identifier' => $clientIdentifier],
			__LINE__, __FILE__, false, '', self::APP)->fetch()))
		{
			throw OAuthServerException::invalidClient();
		}
		$data = Api\Db::strip_array_keys($data, 'client_');

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

        return $client;
    }
}
