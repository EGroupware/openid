<?php
/**
 * EGroupware OpenID Connect / OAuth2 server
 *
 * Overwritten to:
 * - set client-specific access-token TTL (respondToAccessTokenRequest)
 * - carry the response type onto our AuthorizationRequest, so grants can add id_token params
 *   to the redirect response (completeAuthorizationRequest)
 *
 * Implement RFC7662 OAuth 2.0 Token Introspection, still not available upstream (as of
 * league/oauth2-server 9.4 - see https://github.com/thephpleague/oauth2-server/issues/1473).
 *
 * Everything else (enableGrantType, validateAuthorizationRequest, getResponseType,
 * setDefaultScope, ...) is inherited unchanged from League\OAuth2\Server\AuthorizationServer.
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
use League\OAuth2\Server\AuthorizationServer as BaseAuthorizationServer;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use EGroupware\OpenID\IntrospectionValidators\BearerTokenValidator;
use EGroupware\OpenID\IntrospectionValidators\IntrospectionValidatorInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use EGroupware\OpenID\ResponseTypes\BearerTokenIntrospectionResponse;
use EGroupware\OpenID\ResponseTypes\IntrospectionResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationServer extends BaseAuthorizationServer
{
    /**
     * Our own copy of the access-token repository, for the introspector.
     *
     * League's own $accessTokenRepository is a private, promoted constructor property, so a
     * subclass can't reach it - keep a second reference here instead.
     *
     * @var AccessTokenRepositoryInterface
     */
    private $accessTokenRepository;

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

    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        CryptKeyInterface|string $privateKey,
        Key|string $encryptionKey,
        ResponseTypeInterface $responseType = null
    ) {
        parent::__construct($clientRepository, $accessTokenRepository, $scopeRepository, $privateKey, $encryptionKey, $responseType);

        $this->accessTokenRepository = $accessTokenRepository;
    }

    /**
     * Complete an authorization request
     *
     * Reimplemented to carry our response type onto EGroupware\OpenID\RequestTypes\AuthorizationRequest,
     * so eg. Grant\ImplicitGrant can call $authorizationRequest->getResponse()->getExtraParams() to add
     * an id_token to a hybrid-flow redirect.
     */
    public function completeAuthorizationRequest(AuthorizationRequestInterface $authRequest, ResponseInterface $response) : ResponseInterface
    {
        if ($authRequest instanceof \EGroupware\OpenID\RequestTypes\AuthorizationRequest)
        {
            $authRequest->setResponse($this->getResponseType());
        }
        return parent::completeAuthorizationRequest($authRequest, $response);
    }

    /**
     * Return an access token response.
     *
     * Reimplemented to set a client-specific access- and refresh-token TTL, if configured on the
     * client (ClientEntity::getAccessTokenTTL()/getRefreshTokenTTL()), instead of always using the
     * one global TTL per grant type.
     *
     * @throws OAuthServerException
     */
    public function respondToAccessTokenRequest(ServerRequestInterface $request, ResponseInterface $response) : ResponseInterface
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

            return $tokenResponse->generateHttpResponse($response);
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
}
