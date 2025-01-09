<?php

declare(strict_types=1);

namespace Gadget\OAuth\Response;

class AuthCodeResponse extends AbstractAuthResponse implements AuthResponseInterface
{
    /**
     * @param string $state
     * @param string $code
     * @param string|null $error
     * @param string|null $errorDescription
     * @param string|null $errorUri
     * @return void
     */
    public function __construct(
        string $state,
        string $code,
        string|null $error = null,
        string|null $errorDescription = null,
        string|null $errorUri = null
    ) {
        parent::__construct(
            state: $state,
            code: $code,
            error: $error,
            errorDescription: $errorDescription,
            errorUri: $errorUri
        );
    }
}
