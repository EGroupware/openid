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

use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\Entities\ClaimSetInterface;

class UserEntity implements UserEntityInterface, ClaimSetInterface
{
    /**
     * Return the user's identifier.
     *
     * @return mixed
     */
    public function getIdentifier()
    {
        return 1;
    }

    public function getClaims()
    {
        return [
            // profile
            'name' => 'John Smith',
            'family_name' => 'Smith',
            'given_name' => 'John',
            'middle_name' => 'Doe',
            'nickname' => 'JDog',
            'preferred_username' => 'jdogsmith77',
            'profile' => '',
            'picture' => 'avatar.png',
            'website' => 'http://www.google.com',
            'gender' => 'M',
            'birthdate' => '01/01/1990',
            'zoneinfo' => '',
            'locale' => 'US',
            'updated_at' => '01/01/2018',
            // email
            'email' => 'john.doe@example.com',
            'email_verified' => true,
            // phone
            'phone_number' => '(866) 555-5555',
            'phone_number_verified' => true,
            // address
            'address' => '50 any street, any state, 55555',
        ];
    }
}
