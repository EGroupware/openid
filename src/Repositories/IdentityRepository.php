<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * @link https://www.egroupware.org
 * Based on the following MIT Licensed packages:
 * @link https://github.com/steverhoades/oauth2-openid-connect-server
 * @link https://github.com/thephpleague/oauth2-server
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\OpenID\Repositories;

use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use EGroupware\OpenID\Entities\UserEntity;

class IdentityRepository implements IdentityProviderInterface
{
    public function getUserEntityByIdentifier($identifier)
    {
        return new UserEntity();
    }
}
