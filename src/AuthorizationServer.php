<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * Reimplemented/Overwritten to:
 * Set client-specific access-token TTL (respondToAccessTokenRequest)
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

namespace EGroupware\OpenID;

use Defuse\Crypto\Key;
use League\Event\EmitterAwareInterface;
use League\Event\EmitterAwareTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use EGroupware\OpenID\IntrospectionValidators\BearerTokenValidator;
use EGroupware\OpenID\IntrospectionValidators\IntrospectionValidatorInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use EGroupware\OpenID\ResponseTypes\BearerTokenIntrospectionResponse;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use EGroupware\OpenID\ResponseTypes\IntrospectionResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use League\OAuth2\Server\CryptKey;

class AuthorizationServer implements EmitterAwareInterface
{
    use EmitterAwareTrait;

    /**
     * @var GrantTypeInterface[]
     */
    protected $enabledGrantTypes = [];

    /**
     * @var \DateInterval[]
     */
    protected $grantTypeAccessTokenTTL = [];

    /**
     * @var CryptKey
     */
    protected $privateKey;

    /**
     * @var CryptKey
     */
    protected $publicKey;

    /**
     * @var null|ResponseTypeInterface
     */
    protected $responseType;

    /**
     * @var null|IntrospectionResponse
     */
    protected $introspectionResponseType;

    /**
     * @var null|IntrospectionValidatorInterface
     */
    protected $introspectionValidator;

    /**
     * @var null|Introspector
     */
    protected $introspector;

    /**
     * @var ClientRepositoryInterface
     */
    private $clientRepository;

    /**
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

    /**
     * @var ScopeRepositoryInterface
     */
    private $scopeRepository;

    /**
     * @var string|Key
     */
    private $encryptionKey;

    /**
     * @var string
     */
    private $defaultScope = '';

    /**
     * New server instance.
     *
     * @param ClientRepositoryInterface      $clientRepository
     * @param AccessTokenRepositoryInterface $accessTokenRepository
     * @param ScopeRepositoryInterface       $scopeRepository
     * @param CryptKey|string                $privateKey
     * @param string|Key                     $encryptionKey
     * @param null|ResponseTypeInterface     $responseType
     */
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        $privateKey,
        $encryptionKey,
        ResponseTypeInterface $responseType = null
    ) {
        $this->clientRepository = $clientRepository;
        $this->accessTokenRepository = $accessTokenRepository;
        $this->scopeRepository = $scopeRepository;

        if ($privateKey instanceof CryptKey === false) {
            $privateKey = new CryptKey($privateKey);
        }
        $this->privateKey = $privateKey;
        $this->encryptionKey = $encryptionKey;
        $this->responseType = $responseType;
    }

    /**
     * Enable a grant type on the server.
     *
     * @param GrantTypeInterface $grantType
     * @param null|\DateInterval $accessTokenTTL
     */
    public function enableGrantType(GrantTypeInterface $grantType, \DateInterval $accessTokenTTL = null)
    {
        if ($accessTokenTTL instanceof \DateInterval === false) {
            $accessTokenTTL = new \DateInterval('PT1H');
        }

        $grantType->setAccessTokenRepository($this->accessTokenRepository);
        $grantType->setClientRepository($this->clientRepository);
        $grantType->setScopeRepository($this->scopeRepository);
        $grantType->setDefaultScope($this->defaultScope);
        $grantType->setPrivateKey($this->privateKey);
        $grantType->setEmitter($this->getEmitter());
        $grantType->setEncryptionKey($this->encryptionKey);

        $this->enabledGrantTypes[$grantType->getIdentifier()] = $grantType;
        $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()] = $accessTokenTTL;
    }

    /**
     * Validate an authorization request
     *
     * @param ServerRequestInterface $request
     *
     * @throws OAuthServerException
     *
     * @return AuthorizationRequest
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request)
    {
        foreach ($this->enabledGrantTypes as $grantType) {
            if ($grantType->canRespondToAuthorizationRequest($request)) {
                return $grantType->validateAuthorizationRequest($request);
            }
        }

        throw OAuthServerException::unsupportedGrantType();
    }

    /**
     * Complete an authorization request
     *
     * @param AuthorizationRequest $authRequest
     * @param ResponseInterface    $response
     *
     * @return ResponseInterface
     */
    public function completeAuthorizationRequest(AuthorizationRequest $authRequest, ResponseInterface $response)
    {
        if ($authRequest instanceof \EGroupware\OpenID\RequestTypes\AuthorizationRequest)
        {
            $authRequest->setResponse($this->getResponseType());
        }
        return $this->enabledGrantTypes[$authRequest->getGrantTypeId()]
            ->completeAuthorizationRequest($authRequest)
            ->generateHttpResponse($response);
    }

    /**
     * Return an access token response.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     *
     * @throws OAuthServerException
     *
     * @return ResponseInterface
     */
    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseInterface $response)
    {
        foreach ($this->enabledGrantTypes as $grantType) {
            if (!$grantType->canRespondToAccessTokenRequest($request)) {
                continue;
            }
			// set client-specific token TTL, if specified in client
			$client = $grantType->getClient($request);
			if (($ttl = $client->getAccessTokenTTL()))
			{
				$ttl = new \DateInterval($ttl);
			}
			else
			{
				$ttl = $this->grantTypeAccessTokenTTL[$grantType->getIdentifier()];
			}
			if ($grantType->getIdentifier() !== 'implicit' &&
				($refresh_ttl = $client->getRefreshTokenTTL()))
			{
				$grantType->setRefreshTokenTTL(new \DateInterval($refresh_ttl));
			}
            $tokenResponse = $grantType->respondToAccessTokenRequest(
                $request,
                $this->getResponseType(),
                $ttl
            );

            if ($tokenResponse instanceof ResponseTypeInterface) {
                return $tokenResponse->generateHttpResponse($response);
            }
        }

        throw OAuthServerException::unsupportedGrantType();
    }

    /**
     * Set the introspection response type.
     *
     * @param IntrospectionResponse $reponseType
     */
    public function setIntrospectionReponseType(IntrospectionResponse $reponseType)
    {
        $this->introspectionResponseType = $reponseType;
    }

    /**
     * Set the validator used for introspection requests.
     *
     * @param IntrospectionValidatorInterface $introspectionValidator
     */
    public function setIntrospectionValidator(IntrospectionValidatorInterface $introspectionValidator)
    {
        $this->introspectionValidator = $introspectionValidator;
    }

    /**
     * Get the introspection response.
     *
     * @return IntrospectionResponse
     */
    protected function getIntrospectionResponseType()
    {
        if ($this->introspectionResponseType instanceof IntrospectionResponse === false) {
            $this->introspectionResponseType = new BearerTokenIntrospectionResponse();
        }

        return $this->introspectionResponseType;
    }

    /**
     * Get the introspection response
     *
     * @return IntrospectionValidatorInterface
     */
    protected function getIntrospectionValidator()
    {
        if ($this->introspectionValidator instanceof IntrospectionValidatorInterface === false) {
            $this->introspectionValidator = new BearerTokenValidator($this->accessTokenRepository);
			// not included in OAuth2 Server pull request #926
			$this->introspectionValidator->setPrivateKey($this->privateKey);
        }

        return $this->introspectionValidator;
    }

    /**
     * Return an introspection response.
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     *
     * @return ResponseInterface
     */
    public function respondToIntrospectionRequest(ServerRequestInterface $request, ResponseInterface $response)
    {
        $introspector = $this->getIntrospector();

        $introspectionResponse = $introspector->respondToIntrospectionRequest(
            $request,
            $this->getIntrospectionResponseType()
        );

        return $introspectionResponse->generateHttpResponse($response);
    }

    /**
     * Validate an introspection request.
     *
     * @param ServerRequestInterface $request
     */
    public function validateIntrospectionRequest(ServerRequestInterface $request)
    {
        $introspector = $this->getIntrospector();
        $introspector->validateIntrospectionRequest($request);
    }

    /**
     * Returns the introspector.
     *
     * @return Introspector
     */
    private function getIntrospector()
    {
        if (!isset($this->introspector)) {
            $this->introspector = new Introspector(
                $this->accessTokenRepository,
                $this->privateKey,
                $this->getIntrospectionValidator()
            );
        }

        return $this->introspector;
    }

    /**
     * Get the token type that grants will return in the HTTP response.
     *
     * @return ResponseTypeInterface
     */
    protected function getResponseType()
    {
        if ($this->responseType instanceof ResponseTypeInterface === false) {
            $this->responseType = new BearerTokenResponse();
        }

        if ($this->responseType instanceof AbstractResponseType === true) {
            $this->responseType->setPrivateKey($this->privateKey);
        }
        $this->responseType->setEncryptionKey($this->encryptionKey);

        return $this->responseType;
    }

    /**
     * Set the default scope for the authorization server.
     *
     * @param string $defaultScope
     */
    public function setDefaultScope($defaultScope)
    {
        $this->defaultScope = $defaultScope;
    }
}
