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
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use EGroupware\OpenID\Keys;

class BearerTokenValidator implements IntrospectionValidatorInterface
{
    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * @var \League\OAuth2\Server\CryptKey
     */
    protected $privateKey;

    /**
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     * @param ClientRepositoryInterface      $clientRepository used to authenticate the
     *  requesting client (RFC7662 requires the introspection endpoint itself to be protected)
     */
    public function __construct(AccessTokenRepositoryInterface $accessTokenRepository, ClientRepositoryInterface $clientRepository)
    {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->clientRepository = $clientRepository;
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
            $this->isTokenUnverified($token) ||
            $this->isClientUnauthorized($token, $request)
        ) {
            return false;
        }

        return true;
    }

    /**
     * Authenticate the requesting client and check it is the client the token was issued to.
     *
     * RFC7662 requires the introspection endpoint to be protected against token-scanning; we
     * additionally restrict introspection to the client that owns the token (rather than any
     * authenticated client), since there's no use case here for one client introspecting
     * another client's tokens.
     *
     * @param UnencryptedToken       $token
     * @param ServerRequestInterface $request
     *
     * @return bool true if the client is missing, not authenticated, or not the token's owner
     */
    private function isClientUnauthorized(UnencryptedToken $token, ServerRequestInterface $request)
    {
        [$clientId, $clientSecret] = $this->getClientCredentials($request);

        if (!is_string($clientId) || $clientId === '' ||
            !($client = $this->clientRepository->getClientEntity($clientId)) ||
            ($client->isConfidential() && !$this->clientRepository->validateClient($clientId, $clientSecret, null)))
        {
            return true;
        }

        // lcobucci/jwt 5.x's permittedFor() always stores "aud" as an array; we only ever issue
        // tokens for a single client
        $aud = $token->claims()->get('aud');
        $tokenClientId = is_array($aud) ? reset($aud) : $aud;

        return $clientId !== $tokenClientId;
    }

    /**
     * Get the client credentials from the Authorization: Basic header, falling back to
     * client_id/client_secret POST body params (same as the token endpoint accepts).
     *
     * @param ServerRequestInterface $request
     *
     * @return array{0:?string,1:?string}
     */
    private function getClientCredentials(ServerRequestInterface $request)
    {
        $params = (array)$request->getParsedBody();
        $clientId = $params['client_id'] ?? null;
        $clientSecret = $params['client_secret'] ?? null;

        if ($request->hasHeader('Authorization'))
        {
            $header = $request->getHeader('Authorization')[0];
            if (stripos($header, 'Basic ') === 0 &&
                ($decoded = base64_decode(substr($header, 6), true)) !== false &&
                str_contains($decoded, ':'))
            {
                [$clientId, $clientSecret] = explode(':', $decoded, 2);
            }
        }

        return [$clientId, $clientSecret];
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
