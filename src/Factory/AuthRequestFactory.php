<?php

declare(strict_types=1);

namespace Gadget\OAuth\Factory;

use Gadget\Lang\Cast;
use Gadget\OAuth\Entity\AuthRequest;
use Gadget\OAuth\Entity\AuthRequestInterface;
use Gadget\OAuth\Entity\AuthServerInterface;
use Gadget\OAuth\Entity\PkceInterface;

class AuthRequestFactory implements AuthRequestFactoryInterface
{
    /**
     * @param AuthServerFactoryInterface $authServerFactory
     * @param PkceFactoryInterface $pkceFactory
     * @param string $redirectUri
     * @param string $scope
     * @param string|null $responseMode
     * @param string|null $display
     * @param string|null $prompt
     */
    public function __construct(
        private AuthServerFactoryInterface $authServerFactory,
        private PkceFactoryInterface $pkceFactory,
        private string $redirectUri,
        private string $scope,
        private string|null $responseMode = 'form_post',
        private string|null $display = 'page',
        private string|null $prompt = 'select_account'
    ) {
    }


    /**
     * @param mixed $values
     * @return AuthRequestInterface
     */
    public function create(mixed $values): AuthRequestInterface
    {
        $cast = new Cast();
        $values = $cast->toArray($values);

        $authServer = $values['authServer'] ?? null;
        $authServer = $authServer instanceof AuthServerInterface
            ? $authServer
            : $this->authServerFactory->create($authServer);

        $pkce = $values['pkce'] ?? null;
        $pkce = match (true) {
            $pkce instanceof PkceInterface => $pkce,
            $pkce === null => null,
            default => $this->pkceFactory->create($pkce)
        };

        return !isset($values['responseMode'])
            ? $this->createOAuthRequest(
                $authServer,
                $cast->toStringOrNull($values['redirectUri'] ?? null),
                $cast->toStringOrNull($values['scope'] ?? null),
                $cast->toStringOrNull($values['state'] ?? null),
                $pkce,
            )
            : $this->createOIDCRequest(
                $authServer,
                $cast->toStringOrNull($values['redirectUri'] ?? null),
                $cast->toStringOrNull($values['scope'] ?? null),
                $cast->toStringOrNull($values['state'] ?? null),
                $pkce,
                $cast->toStringOrNull($values['responseMode']),
                $cast->toStringOrNull($values['nonce'] ?? null),
                $cast->toStringOrNull($values['display'] ?? null),
                $cast->toStringOrNull($values['prompt'] ?? null),
                $cast->toIntOrNull($values['maxAge'] ?? null),
                $cast->toStringOrNull($values['uiLocales'] ?? null),
                $cast->toStringOrNull($values['idTokenHint'] ?? null),
                $cast->toStringOrNull($values['loginTokenHint'] ?? null)
            );
    }


    /**
     * @param AuthServerInterface|null $authServer
     * @param string|null $redirectUri
     * @param string|null $scope
     * @param string|null $state
     * @param PkceInterface|null $pkce
     *
     * @return AuthRequestInterface
     */
    public function createOAuthRequest(
        AuthServerInterface|null $authServer = null,
        string|null $redirectUri = null,
        string|null $scope = null,
        string|null $state = null,
        PkceInterface|null $pkce = null
    ): AuthRequestInterface {
        return new AuthRequest(
            $authServer ?? $this->authServerFactory->createAuthServer(),
            $redirectUri ?? $this->redirectUri,
            $scope ?? $this->scope,
            $state ?? bin2hex(random_bytes(32)),
            $pkce
        );
    }


    /**
     * @param AuthServerInterface|null $authServer
     * @param string|null $redirectUri
     * @param string|null $scope
     * @param string|null $state
     * @param PkceInterface|null $pkce
     * @param string|null $responseMode
     * @param string|null $nonce
     * @param string|null $display
     * @param string|null $prompt
     * @param int|null $maxAge
     * @param string|null $uiLocales
     * @param string|null $idTokenHint
     * @param string|null $loginTokenHint
     *
     * @return AuthRequestInterface
     */
    public function createOIDCRequest(
        AuthServerInterface|null $authServer = null,
        string|null $redirectUri = null,
        string|null $scope = null,
        string|null $state = null,
        PkceInterface|null $pkce = null,
        string|null $responseMode = null,
        string|null $nonce = null,
        string|null $display = null,
        string|null $prompt = null,
        int|null $maxAge = null,
        string|null $uiLocales = null,
        string|null $idTokenHint = null,
        string|null $loginTokenHint = null
    ): AuthRequestInterface {
        return new AuthRequest(
            $authServer ?? $this->authServerFactory->createAuthServer(),
            $redirectUri ?? $this->redirectUri,
            $scope ?? $this->scope,
            $state ?? bin2hex(random_bytes(32)),
            $pkce,
            $responseMode ?? $this->responseMode,
            $nonce ?? bin2hex(random_bytes(32)),
            $display ?? $this->display,
            $prompt ?? $this->prompt,
            $maxAge,
            $uiLocales,
            $idTokenHint,
            $loginTokenHint
        );
    }
}
