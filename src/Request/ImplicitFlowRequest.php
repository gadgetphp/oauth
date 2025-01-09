<?php

declare(strict_types=1);

namespace Gadget\OAuth\Request;

use Gadget\OAuth\Pkce\PkceInterface;
use Gadget\OAuth\Server\AuthServerInterface;

class ImplicitFlowRequest extends AbstractAuthRequest implements AuthRequestInterface
{
       /**
     * @param AuthServerInterface $authServer
     * @param string $responseType
     * @param string $redirectUri
     * @param string|null $scope
     * @param string $state
     * @param string $nonce
     * @param PkceInterface|null $pkce
     * @param string|null $responseMode
     * @param string|null $display
     * @param string|null $prompt
     * @param int|null $maxAge
     * @param string|null $uiLocales
     * @param string|null $idTokenHint
     * @param string|null $loginTokenHint
     */
    public function __construct(
        AuthServerInterface $authServer,
        string $responseType,
        string $redirectUri,
        string|null $scope,
        string $state,
        string $nonce,
        PkceInterface|null $pkce = null,
        string|null $responseMode = null,
        string|null $display = null,
        string|null $prompt = null,
        int|null $maxAge = null,
        string|null $uiLocales = null,
        string|null $idTokenHint = null,
        string|null $loginTokenHint = null
    ) {
        parent::__construct(
            $authServer,
            $responseType,
            $redirectUri,
            $scope,
            $state,
            $pkce,
            $responseMode,
            $nonce,
            $display,
            $prompt,
            $maxAge,
            $uiLocales,
            $idTokenHint,
            $loginTokenHint
        );
    }
}
