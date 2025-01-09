<?php

declare(strict_types=1);

namespace Gadget\OAuth\Request;

use Gadget\Lang\Cast;
use Gadget\OAuth\Pkce\PkceFactoryInterface;
use Gadget\OAuth\Pkce\PkceInterface;
use Gadget\OAuth\Server\AuthServerFactoryInterface;
use Gadget\OAuth\Server\AuthServerInterface;

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

        $responseType = $cast->toString($values['response_type'] ?? 'code');
        $authServer = $this->authServerFactory->createAuthServer($cast->toStringOrNull($values['auth_uri'] ?? null));
        $pkce = isset($values['code_challenge_method'])
            ? $this->pkceFactory->createPkce($cast->toString($values['code_challenge_method']))
            : null;

        return $responseType === 'code'
            ? $this->createAuthCodeRequest(
                $authServer,
                $cast->toStringOrNull($values['redirect_uri'] ?? null),
                $cast->toStringOrNull($values['scope'] ?? null),
                $cast->toStringOrNull($values['state'] ?? null),
                $pkce,
            )
            : $this->createImplicitFlowRequest(
                $authServer,
                $responseType,
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
    public function createAuthCodeRequest(
        AuthServerInterface|null $authServer = null,
        string|null $redirectUri = null,
        string|null $scope = null,
        string|null $state = null,
        PkceInterface|null $pkce = null
    ): AuthRequestInterface {
        return new AuthCodeRequest(
            $authServer ?? $this->authServerFactory->createAuthServer(),
            $redirectUri ?? $this->redirectUri,
            $scope ?? $this->scope,
            $state ?? bin2hex(random_bytes(32)),
            $pkce
        );
    }


    /**
     * @param AuthServerInterface|null $authServer
     * @param string $responseType
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
    public function createImplicitFlowRequest(
        AuthServerInterface|null $authServer = null,
        string $responseType = 'id_token',
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
        return new ImplicitFlowRequest(
            $authServer ?? $this->authServerFactory->createAuthServer(),
            $responseType,
            $redirectUri ?? $this->redirectUri,
            $scope ?? $this->scope,
            $state ?? bin2hex(random_bytes(32)),
            $nonce ?? bin2hex(random_bytes(32)),
            $pkce,
            $responseMode ?? $this->responseMode,
            $display ?? $this->display,
            $prompt ?? $this->prompt,
            $maxAge,
            $uiLocales,
            $idTokenHint,
            $loginTokenHint
        );
    }
}
