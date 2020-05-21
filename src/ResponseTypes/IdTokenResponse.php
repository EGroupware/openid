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
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @link https://github.com/thephpleague/oauth2-server
 */

namespace EGroupware\OpenID\ResponseTypes;

use EGroupware\OpenID\RequestTypes\AuthorizationRequest;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\Entities\ClaimSetInterface;
use OpenIDConnectServer\IdTokenResponse as BaseIdTokenResponse;
use EGroupware\Api\Header\Http;

class IdTokenResponse extends BaseIdTokenResponse
{
	/**
	 * Reimplement to:
	 * - use X-Forwarded-Host header, if available, instead of Host
	 *
	 * Fixes JWT don't validate for client in certain proxying situations because of wrong issuer (eg. internal IP).
	 *
	 * @param AccessTokenEntityInterface $accessToken
	 * @param UserEntityInterface $userEntity
	 * @return Builder
	 */
	protected function getBuilder(AccessTokenEntityInterface $accessToken, UserEntityInterface $userEntity)
	{
		// Add required id_token claims
		$builder = (new Builder())
			->setAudience($accessToken->getClient()->getIdentifier())
			->setIssuer(Http::schema().'://' . Http::host())
			->setIssuedAt(time())
			->setExpiration($accessToken->getExpiryDateTime()->getTimestamp())
			->setSubject($userEntity->getIdentifier());

		return $builder;
	}

	protected $nonce;

	/**
	 * Set nonce for id_token response, as it's required by OpenID Connect spec
	 *
	 * @param string $nonce
	 */
	public function setNonce($nonce)
	{
		$this->nonce = $nonce;
	}

	/**
	 * Reimplemented to:
	 * - make it public, to add id_token responses for implicit grant
	 * - add nonce as claim as required by OpenID Connect spec
	 *
	 * @param AccessTokenEntityInterface $accessToken
	 * @return array
	 */
	public function getExtraParams(AccessTokenEntityInterface $accessToken, AuthorizationRequest $authorizationRequest=null)
	{
		if (false === $this->isOpenIDRequest($accessToken->getScopes())) {
			return [];
		}

		/** @var UserEntityInterface $userEntity */
		$userEntity = $this->identityProvider->getUserEntityByIdentifier($accessToken->getUserIdentifier());

		if (false === is_a($userEntity, UserEntityInterface::class)) {
			throw new \RuntimeException('UserEntity must implement UserEntityInterface');
		} else if (false === is_a($userEntity, ClaimSetInterface::class)) {
			throw new \RuntimeException('UserEntity must implement ClaimSetInterface');
		}

		// Add required id_token claims
		$builder = $this->getBuilder($accessToken, $userEntity);

		// Need a claim factory here to reduce the number of claims by provided scope.
		$claims = $this->claimExtractor->extract($accessToken->getScopes(), $userEntity->getClaims());

		// if a nonce is given, we have to return it as claim
		if ($authorizationRequest && ($nonce = $authorizationRequest->getNonce()))
		{
			$claims['nonce'] = $nonce;
		}
		elseif (!empty($this->nonce))
		{
			$claims['nonce'] = $this->nonce;
		}

		foreach ($claims as $claimName => $claimValue) {
			$builder->set($claimName, $claimValue);
		}

		$token = $builder
			->sign(new Sha256(), new Key($this->privateKey->getKeyPath(), $this->privateKey->getPassPhrase()))
			->getToken();

		return [
			'id_token' => (string) $token
		];
	}

	/**
	 * @param ScopeEntityInterface[] $scopes
	 * @return bool
	 */
	private function isOpenIDRequest($scopes)
	{
		// Verify scope and make sure openid exists.
		$valid  = false;

		foreach ($scopes as $scope) {
			if ($scope->getIdentifier() === 'openid') {
				$valid = true;
				break;
			}
		}

		return $valid;
	}
}