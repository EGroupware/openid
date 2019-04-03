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

namespace EGroupware\OpenID\Entities;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class AccessTokenEntity implements AccessTokenEntityInterface
{
    use AccessTokenTrait, TokenEntityTrait, EntityTrait;
}
