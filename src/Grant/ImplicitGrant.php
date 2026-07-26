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

namespace EGroupware\OpenID\Grant;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AbstractAuthorizeGrant;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface as BaseAuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use DateInterval;
use DateTime;
use LogicException;
use EGroupware\OpenID\RequestTypes\AuthorizationRequest;
use EGroupware\OpenID\Repositories\ClientRepository;

/**
 * Class ImplicitGrant
 *
 * Unfortunately this class has to be a copied and modified version of
 * League\OAuth2\Server\Grant\ImplicitGrant to be able to respond to
 * OpenIDConnect's multiple space-separated respond_type(s):
 * - token (original one of ImplicitGrant) returning access_token as Bearer token
 * - id_token returning access_token as JWT
 * - code returning additional auth-code
 * At least one of "token" or "id_token" is required, to respond!
 *
 * league/oauth2-server 9's own ImplicitGrant dropped this multi-response_type / hybrid-flow
 * support entirely (it now only ever handles response_type=token, and no longer accepts an
 * AuthCodeRepository), so we extend AbstractAuthorizeGrant directly instead of league's
 * ImplicitGrant, same as before.
 *
 * @package EGroupware\OpenID\Grant
 */
class ImplicitGrant extends AbstractAuthorizeGrant
{
	use Traits\GetClientTrait;

	/**
	 * @var DateInterval
	 */
	private $accessTokenTTL;

	/**
	 * @var string
	 */
	private $queryDelimiter;

	/**
	 * @var DateInterval
	 */
	private $authCodeTTL;

	/**
	 * @param AuthCodeRepositoryInterface $authCodeRepository
	 * @param DateInterval $authCodeTTL
	 * @param DateInterval $accessTokenTTL
	 * @param string       $queryDelimiter
	 */
	public function __construct(
		AuthCodeRepositoryInterface $authCodeRepository,
		DateInterval $authCodeTTL,
		DateInterval $accessTokenTTL,
		$queryDelimiter = '#')
	{
		$this->accessTokenTTL = $accessTokenTTL;
		$this->queryDelimiter = $queryDelimiter;

		// to be able to respond to response_type=code
		$this->setAuthCodeRepository($authCodeRepository);
		$this->authCodeTTL = $authCodeTTL;
		$this->refreshTokenTTL = new DateInterval('P1M');
	}

	/**
	 * @param DateInterval $refreshTokenTTL
	 *
	 * @throw LogicException
	 */
	public function setRefreshTokenTTL(DateInterval $refreshTokenTTL) : void
	{
		throw new LogicException('The Implicit Grant does not return refresh tokens');
	}

	/**
	 * @param RefreshTokenRepositoryInterface $refreshTokenRepository
	 *
	 * @throw LogicException
	 */
	public function setRefreshTokenRepository(RefreshTokenRepositoryInterface $refreshTokenRepository) : void
	{
		throw new LogicException('The Implicit Grant does not return refresh tokens');
	}

	/**
	 * {@inheritdoc}
	 */
	public function canRespondToAccessTokenRequest(ServerRequestInterface $request) : bool
	{
		return false;
	}

	/**
	 * Return the grant identifier that can be used in matching up requests.
	 *
	 * @return string
	 */
	public function getIdentifier() : string
	{
		return 'implicit';
	}

	/**
	 * Respond to an incoming request.
	 *
	 * @param ServerRequestInterface $request
	 * @param ResponseTypeInterface  $responseType
	 * @param DateInterval           $accessTokenTTL
	 *
	 * @return ResponseTypeInterface
	 */
	public function respondToAccessTokenRequest(
		ServerRequestInterface $request,
		ResponseTypeInterface $responseType,
		DateInterval $accessTokenTTL
	) : ResponseTypeInterface {
		throw new LogicException('This grant does not used this method');
	}

	/**
	 * Overwritten/modified to respond to all response_type(s) containing (space-separated)
	 * "token" or "id_token", not just "token" itself
	 *
	 * {@inheritdoc}
	 */
	public function canRespondToAuthorizationRequest(ServerRequestInterface $request) : bool
	{
		return (
			isset($request->getQueryParams()['response_type'])
			&& array_intersect(['token', 'id_token'], explode(' ', $request->getQueryParams()['response_type']))
			&& isset($request->getQueryParams()['client_id'])
		);
	}

	/**
	 * {@inheritdoc}
	 */
	public function validateAuthorizationRequest(ServerRequestInterface $request) : BaseAuthorizationRequest
	{
		$clientId = $this->getQueryStringParameter(
			'client_id',
			$request,
			$this->getServerParameter('PHP_AUTH_USER', $request)
		);

		if (is_null($clientId)) {
			throw OAuthServerException::invalidRequest('client_id');
		}

		$client = $this->getClientEntityOrFail($clientId, $request);

		$redirectUri = $this->getQueryStringParameter('redirect_uri', $request);

		if ($redirectUri !== null) {
			$this->validateRedirectUri($redirectUri, $client, $request);
		} elseif (is_array($client->getRedirectUri()) && count($client->getRedirectUri()) !== 1
			|| empty($client->getRedirectUri())) {
			$this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
			throw OAuthServerException::invalidClient($request);
		} else {
			$redirectUri = is_array($client->getRedirectUri())
				? $client->getRedirectUri()[0]
				: $client->getRedirectUri();
		}

		$scopes = $this->validateScopes(
			$this->getQueryStringParameter('scope', $request, $this->defaultScope),
			$redirectUri
		);

		$stateParameter = $this->getQueryStringParameter('state', $request);

		$response_types = explode(' ', $request->getQueryParams()['response_type']);
		// validate that response_code must container at least one of "token" or "id_token" plus optional "code"
		if (!array_intersect($response_types, ['token', 'id_token']) || array_diff($response_types, ['token', 'id_token', 'code']))
		{
			throw OAuthServerException::invalidRequest('response_type');
		}

		$authorizationRequest = new AuthorizationRequest();
		$authorizationRequest->setGrantTypeId($this->getIdentifier());
		$authorizationRequest->setClient($client);
		$authorizationRequest->setRedirectUri($redirectUri);
		$authorizationRequest->setResponseTypes($response_types);
		$authorizationRequest->setNonce($request->getQueryParams()['nonce'] ?? null);

		if ($stateParameter !== null) {
			$authorizationRequest->setState($stateParameter);
		}

		$authorizationRequest->setScopes($scopes);

		return $authorizationRequest;
	}

	/**
	 * {@inheritdoc}
	 */
	public function completeAuthorizationRequest(BaseAuthorizationRequest $authorizationRequest) : ResponseTypeInterface
	{
		if ($authorizationRequest->getUser() instanceof UserEntityInterface === false) {
			throw new LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
		}

		$finalRedirectUri = ($authorizationRequest->getRedirectUri() === null)
			? is_array($authorizationRequest->getClient()->getRedirectUri())
				? $authorizationRequest->getClient()->getRedirectUri()[0]
				: $authorizationRequest->getClient()->getRedirectUri()
			: $authorizationRequest->getRedirectUri();

		// The user approved the client, redirect them back with an access token
		if ($authorizationRequest->isAuthorizationApproved() === true) {
			// Finalize the requested scopes
			$finalizedScopes = $this->scopeRepository->finalizeScopes(
				$authorizationRequest->getScopes(),
				$this->getIdentifier(),
				$authorizationRequest->getClient(),
				$authorizationRequest->getUser()->getIdentifier()
			);

			$accessToken = $this->issueAccessToken(
				$this->accessTokenTTL,
				$authorizationRequest->getClient(),
				$authorizationRequest->getUser()->getIdentifier(),
				$finalizedScopes
			);

			$params = [
				'state' => $authorizationRequest->getState(),
			];

			// respond to response_type=token
			if ($authorizationRequest instanceof AuthorizationRequest && $authorizationRequest->needResponseType('token'))
			{
				$params += [
					'access_token' => $accessToken->toString(),
					'token_type'   => 'Bearer',
					'expires_in'   => $accessToken->getExpiryDateTime()->getTimestamp() - (new DateTime())->getTimestamp(),
				];
			}

			// respond to response_type=id_token
			if ($authorizationRequest instanceof AuthorizationRequest && $authorizationRequest->needResponseType('id_token'))
			{
				$params += $authorizationRequest->getResponse()->getExtraParams($accessToken, $authorizationRequest);
			}

			// responde to response_type=code
			if ($authorizationRequest instanceof AuthorizationRequest && $authorizationRequest->needResponseType('code'))
			{
				$authCode = $this->issueAuthCode(
					$this->authCodeTTL,
					$authorizationRequest->getClient(),
					$authorizationRequest->getUser()->getIdentifier(),
					$authorizationRequest->getRedirectUri(),
					$authorizationRequest->getScopes()
				);

				// same encrypted-JSON-payload format as League\OAuth2\Server\Grant\AuthCodeGrant
				// (and our own Grant\AuthCodeGrant::respondToAccessTokenRequest(), which decrypts it)
				$params += [
					'code' => $this->encrypt(json_encode([
						'client_id'             => $authCode->getClient()->getIdentifier(),
						'redirect_uri'          => $authCode->getRedirectUri(),
						'auth_code_id'          => $authCode->getIdentifier(),
						'scopes'                => $authCode->getScopes(),
						'user_id'               => $authCode->getUserIdentifier(),
						'expire_time'           => (new \DateTimeImmutable())->add($this->authCodeTTL)->getTimestamp(),
						'code_challenge'        => $authorizationRequest->getCodeChallenge(),
						'code_challenge_method' => $authorizationRequest->getCodeChallengeMethod(),
					])),
				];
			}

			$response = new RedirectResponse();
			$response->setRedirectUri(
				$this->makeRedirectUri(
					$finalRedirectUri,
					$params,
					$this->queryDelimiter
				)
			);

			return $response;
		}

		// The user denied the client, redirect them back with an error
		throw OAuthServerException::accessDenied(
			'The user denied the request',
			$this->makeRedirectUri(
				$finalRedirectUri,
				[
					'state' => $authorizationRequest->getState(),
				]
			)
		);
	}
}
