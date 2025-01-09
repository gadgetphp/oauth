<?php

declare(strict_types=1);

namespace Gadget\OAuth\Request;

use Gadget\OAuth\Pkce\PkceInterface;
use Gadget\OAuth\Server\AuthServerInterface;

class AuthCodeRequest extends AbstractAuthRequest implements AuthRequestInterface
{
    /**
     * @param AuthServerInterface $authServer
     * @param string $redirectUri
     * @param string|null $scope
     * @param string $state
     * @param PkceInterface|null $pkce
     */
    public function __construct(
        AuthServerInterface $authServer,
        string $redirectUri,
        string|null $scope,
        string $state,
        PkceInterface|null $pkce = null
    ) {
        parent::__construct(
            authServer: $authServer,
            responseType: 'code',
            redirectUri: $redirectUri,
            scope: $scope,
            state: $state,
            pkce: $pkce
        );
    }
}
