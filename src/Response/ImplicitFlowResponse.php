<?php

declare(strict_types=1);

namespace Gadget\OAuth\Response;

class ImplicitFlowResponse extends AbstractAuthResponse implements AuthResponseInterface
{
    /**
     * @param string $state
     * @param string $idToken
     * @param string|null $accessToken
     * @param string|null $tokenType
     * @param int|null $expiresIn
     * @param string|null $error
     * @param string|null $errorDescription
     * @param string|null $errorUri
     * @return void
     */
    public function __construct(
        string $state,
        string $idToken,
        string|null $accessToken = null,
        string|null $tokenType = null,
        int|null $expiresIn = null,
        string|null $error = null,
        string|null $errorDescription = null,
        string|null $errorUri = null
    ) {
        parent::__construct(
            state: $state,
            idToken: $idToken,
            accessToken: $accessToken,
            tokenType: $tokenType,
            expiresIn: $expiresIn,
            error: $error,
            errorDescription: $errorDescription,
            errorUri: $errorUri
        );
    }
}
