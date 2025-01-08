<?php

declare(strict_types=1);

namespace Gadget\OAuth\Entity;

class AuthResponse implements AuthResponseInterface
{
    /**
     * @param string $code
     * @param string $state
     * @param string|null $error
     * @param string|null $errorDescription
     * @param string|null $errorUri
     * @return void
     */
    public function __construct(
        private string $code,
        private string $state,
        private string|null $error = null,
        private string|null $errorDescription = null,
        private string|null $errorUri = null
    ) {
    }


    /**
     * @return string
     */
    public function getCode(): string
    {
        return $this->code;
    }


    /**
     * @return string
     */
    public function getState(): string
    {
        return $this->state;
    }


    /**
     * @return string|null
     */
    public function getError(): string|null
    {
        return $this->error;
    }


    /**
     * @return string|null
     */
    public function getErrorDescription(): string|null
    {
        return $this->errorDescription;
    }


    /**
     * @return string|null
     */
    public function getErrorUri(): string|null
    {
        return $this->errorUri;
    }
}
