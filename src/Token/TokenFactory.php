<?php

declare(strict_types=1);

namespace Gadget\OAuth\Token;

use Firebase\JWT\CachedKeySet;
use Firebase\JWT\JWT;
use Gadget\Lang\Cast;
use Gadget\OAuth\Request\AuthRequestInterface;
use Gadget\OAuth\Response\AuthResponseInterface;
use Gadget\OAuth\Server\AuthServerInterface;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

class TokenFactory implements TokenFactoryInterface
{
    /**
     * @param ClientInterface $client
     * @param RequestFactoryInterface $requestFactory
     * @param CacheItemPoolInterface $cache
     */
    public function __construct(
        private ClientInterface $client,
        private RequestFactoryInterface $requestFactory,
        private CacheItemPoolInterface $cache
    ) {
    }


    /**
     * @param mixed $values
     * @return TokenInterface
     */
    public function create(mixed $values): TokenInterface
    {
        $cast = new Cast();
        $values = $cast->toArrayOrNull($values) ?? [];
        $authRequest = $values['authRequest'] ?? null;
        $authResponse = $values['authResponse'] ?? null;
        $authServer = $values['authServer'] ?? null;
        $token = $values['token'] ?? null;

        if ($authRequest instanceof AuthRequestInterface && $authResponse instanceof AuthResponseInterface) {
            return $this->createToken(
                $authRequest,
                $authResponse
            );
        }

        if ($authServer instanceof AuthServerInterface && $token instanceof TokenInterface) {
            return $this->refreshToken($authServer, $token);
        }

        throw new \RuntimeException();
    }


    /**
     * @param AuthRequestInterface $authRequest
     * @param AuthResponseInterface $authResponse
     * @return TokenInterface
     */
    public function createToken(
        AuthRequestInterface $authRequest,
        AuthResponseInterface $authResponse
    ): TokenInterface {
        if ($authRequest->getState() !== $authResponse->getState()) {
            throw new \RuntimeException();
        }

        if ($authResponse->getError() !== null) {
            throw new \RuntimeException($authResponse->getError());
        }

        $token = match ($authRequest->getResponseType()) {
            'id_token',
            'id_token token' => new Token(
                tokenType: $authResponse->getTokenType() ?? 'Bearer',
                scope: $authRequest->getScope(),
                expiresIn: $authResponse->getExpiresIn(),
                accessToken: $authResponse->getAccessToken(),
                idToken: $this->createIdToken(
                    $authRequest->getAuthServer(),
                    $authResponse->getIdToken()
                ),
                refreshToken: null,
            ),

            'code',
            'code id_token',
            'code token',
            'code id_token token' => $this->invoke($authRequest->getAuthServer(), [
                'grant_type' => 'authorization_code',
                'code' => $authResponse->getCode(),
                'redirect_uri' => $authRequest->getRedirectUri(),
                'client_id' => $authRequest->getAuthServer()->getClientId(),
                'client_secret' => $authRequest->getAuthServer()->getClientSecret(),
                'code_verifier' => $authRequest->getPkce()?->getCodeVerifier()
            ]),

            default => throw new \RuntimeException()
        };

        return $token;
    }


    /**
     * @param AuthServerInterface $authServer
     * @param TokenInterface $token
     * @return TokenInterface
     */
    public function refreshToken(
        AuthServerInterface $authServer,
        TokenInterface $token
    ): TokenInterface {
        return $token->getRefreshToken() !== null
            ? $this->invoke($authServer, [
                'grant_type' => 'refresh_token',
                'refresh_token' => $token->getRefreshToken(),
                'client_id' => $authServer->getClientId(),
                'client_secret' => $authServer->getClientSecret()
            ])
            : throw new \RuntimeException();
    }


    /**
     * @param AuthServerInterface $authServer
     * @param mixed[] $params
     * @return Token
     */
    private function invoke(
        AuthServerInterface $authServer,
        array $params
    ): Token {
        $request = $this->requestFactory
            ->createRequest('POST', $authServer->getTokenUri())
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $request
            ->getBody()
            ->write(http_build_query(
                $params,
                "",
                null,
                PHP_QUERY_RFC3986
            ));

        $response = $this->client->sendRequest($request);
        if ($response->getStatusCode() !== 200) {
            throw new \RuntimeException("Invalid response: " . $response->getStatusCode());
        }

        $cast = new Cast();
        $values = $cast->toArray($response->getBody()->getContents());
        return new Token(
            tokenType: $cast->toString($values['token_type'] ?? ''),
            scope: $cast->toStringOrNull($values['scope'] ?? null),
            expiresIn: $cast->toIntOrNull($values['expires_in'] ?? null),
            accessToken: $cast->toStringOrNull($values['access_token'] ?? null),
            idToken: $this->createIdToken(
                $authServer,
                $cast->toStringOrNull($values['id_token'] ?? null)
            ),
            refreshToken: $cast->toStringOrNull($values['refresh_token'] ?? null),
        );
    }


    /**
     * @param AuthServerInterface $authServer
     * @param string|null $idToken
     * @return IdTokenInterface
     */
    private function createIdToken(
        AuthServerInterface $authServer,
        string|null $idToken
    ): IdTokenInterface|null {
        if ($idToken === null) {
            return null;
        }

        $jwks = new CachedKeySet(
            $authServer->getJwksUri(),
            $this->client,
            $this->requestFactory,
            $this->cache,
            null,
            false,
            'RS256'
        );

        JWT::$leeway = 30;
        return new IdToken(
            $idToken,
            (new Cast())->toArray(JWT::decode($idToken, $jwks))
        );
    }
}
