<?php

declare(strict_types=1);

namespace Gadget\OAuth\Factory;

use Gadget\Lang\Cast;
use Gadget\OAuth\Entity\AuthRequestInterface;
use Gadget\OAuth\Entity\AuthResponseInterface;
use Gadget\OAuth\Entity\AuthServerInterface;
use Gadget\OAuth\Entity\Token;
use Gadget\OAuth\Entity\TokenInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

class TokenFactory implements TokenFactoryInterface
{
    /**
     * @param ClientInterface $client
     * @param RequestFactoryInterface $requestFactory
     */
    public function __construct(
        private ClientInterface $client,
        private RequestFactoryInterface $requestFactory
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

        return $this->invoke(
            $authRequest->getAuthServer()->getTokenUri(),
            [
                'grant_type' => 'authorization_code',
                'code' => $authResponse->getCode(),
                'redirect_uri' => $authRequest->getRedirectUri(),
                'client_id' => $authRequest->getAuthServer()->getClientId(),
                'client_secret' => $authRequest->getAuthServer()->getClientSecret(),
                'code_verifier' => $authRequest->getPkce()?->getCodeVerifier()
            ]
        );
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
        if ($token->getRefreshToken() === null) {
            throw new \RuntimeException();
        }

        return $this->invoke(
            $authServer->getTokenUri(),
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $token->getRefreshToken(),
                'client_id' => $authServer->getClientId(),
                'client_secret' => $authServer->getClientSecret()
            ]
        );
    }


    /**
     * @param string $tokenUri
     * @param mixed[] $params
     * @return Token
     */
    private function invoke(
        string $tokenUri,
        array $params
    ): Token {
        $request = $this->requestFactory
            ->createRequest('POST', $tokenUri)
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
            idToken: $cast->toStringOrNull($values['id_token'] ?? null),
            refreshToken: $cast->toStringOrNull($values['refresh_token'] ?? null),
        );
    }
}
