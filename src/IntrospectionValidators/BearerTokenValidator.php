<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * Implement RFC7662 OAuth 2.0 Token Introspection
 * Until OAuth2 server pull request #925 is not merged:
 * @link https://github.com/thephpleague/oauth2-server/pull/925
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

namespace EGroupware\OpenID\IntrospectionValidators;

use InvalidArgumentException;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use EGroupware\OpenID\Keys;

class BearerTokenValidator implements IntrospectionValidatorInterface
{
    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var \League\OAuth2\Server\CryptKey
     */
    protected $privateKey;

    /**
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     */
    public function __construct(AccessTokenRepositoryInterface $accessTokenRepository)
    {
        $this->accessTokenRepository = $accessTokenRepository;
    }

    /**
     * Set the private key.
     *
     * @param \League\OAuth2\Server\CryptKey $key
     */
    public function setPrivateKey(CryptKey $key)
    {
        $this->privateKey = $key;
    }

    /**
     * {@inheritdoc}
     */
    public function validateIntrospection(ServerRequestInterface $request)
    {
        try {
            $token = $this->getTokenFromRequest($request);
        } catch (InvalidArgumentException $e) {
            return false;
        }

        if (
            $this->isTokenRevoked($token) ||
            $this->isTokenExpired($token) ||
            $this->isTokenUnverified($token)
        ) {
            return false;
        }

        return true;
    }

    /**
     * Gets the token from the request body.
     *
     * @param ServerRequestInterface $request
     *
     * @return UnencryptedToken
     */
    public function getTokenFromRequest(ServerRequestInterface $request)
    {
        $jwt = $request->getParsedBody()['token'] ?? null;

        if (!is_string($jwt) || $jwt === '')
        {
            throw new InvalidArgumentException('No token given');
        }

        $token = (new Keys())->jwtConfiguration()->parser()->parse($jwt);

        if (!($token instanceof UnencryptedToken))
        {
            throw new InvalidArgumentException('Not an unencrypted token');
        }

        return $token;
    }

    /**
     * Checks whether the token is unverified.
     *
     * @param UnencryptedToken $token
     *
     * @return bool
     */
    private function isTokenUnverified(UnencryptedToken $token)
    {
        $config = (new Keys())->jwtConfiguration();

        return !$config->validator()->validate($token, new SignedWith($config->signer(), $config->verificationKey()));
    }

    /**
     * Ensure access token hasn't expired.
     *
     * @param UnencryptedToken $token
     *
     * @return bool
     */
    private function isTokenExpired(UnencryptedToken $token)
    {
        $config = (new Keys())->jwtConfiguration();

        return !$config->validator()->validate($token, new StrictValidAt(SystemClock::fromUTC()));
    }

    /**
     * Check if the given token is revoked.
     *
     * @param UnencryptedToken $token
     *
     * @return bool
     */
    private function isTokenRevoked(UnencryptedToken $token)
    {
        return $this->accessTokenRepository->isAccessTokenRevoked($token->claims()->get('jti'));
    }
}
