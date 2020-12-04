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

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class AccessTokenEntity implements AccessTokenEntityInterface
{
	use AccessTokenTrait, TokenEntityTrait, EntityTrait, Traits\UserAgentTrait, Traits\IdTrait;

	/**
	 * Generate a JWT from the access token
	 *
	 * @param CryptKey $privateKey
	 * @param array $extra_claims $name => $value pairs with exra claims
	 *
	 * @return Token
	 */
	public function convertToJWT(CryptKey $privateKey, array $extra_claims=null)
	{
		$builder = new Builder();
		$builder->setAudience($this->getClient()->getIdentifier())
			->setId($this->getIdentifier(), true)
			->setIssuedAt(time())
			->setNotBefore(time())
			->setExpiration($this->getExpiryDateTime()->getTimestamp())
			->setSubject($this->getUserIdentifier())
			->set('scopes', $this->getScopes());

		foreach($extra_claims as $name => $value)
		{
			$builder->set($name, $value);
		}
		return $builder->sign(new Sha256(), new Key($privateKey->getKeyPath(), $privateKey->getPassPhrase()))
			->getToken();
	}
}
