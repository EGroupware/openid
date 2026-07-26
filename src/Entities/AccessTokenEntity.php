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

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Builder;
use League\OAuth2\Server\CryptKeyInterface;
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
	 * Reimplemented (overriding AccessTokenTrait::toString()'s private convertToJWT()) to allow
	 * adding extra claims - used by Token::accessToken() for programmatic token generation eg. for
	 * "remember me".
	 *
	 * @param CryptKeyInterface|null $privateKey null to use the key set via setPrivateKey()
	 * @param array $extra_claims $name => $value pairs with extra claims
	 *
	 * @return Token
	 */
	public function convertToJWT(?CryptKeyInterface $privateKey=null, array $extra_claims=array())
	{
		$privateKey ??= $this->privateKey;

		$builder = (new Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates()))
			->permittedFor($this->getClient()->getIdentifier())
			->identifiedBy($this->getIdentifier())
			->issuedAt(new DateTimeImmutable('now', new \DateTimeZone('UTC')))
			->canOnlyBeUsedAfter(new DateTimeImmutable('now', new \DateTimeZone('UTC')))
			->expiresAt($this->getExpiryDateTime())
			->relatedTo((string)$this->getUserIdentifier())
			->withClaim('scopes', $this->getScopes());

		foreach($extra_claims as $name => $value)
		{
			$builder = $builder->withClaim($name, $value);
		}
		return $builder->getToken(new Sha256(),
			InMemory::plainText($privateKey->getKeyContents(), (string)$privateKey->getPassPhrase()));
	}
}