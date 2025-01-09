<?php

declare(strict_types=1);

namespace Gadget\OAuth\Response;

abstract class AbstractAuthResponse implements AuthResponseInterface
{
    /**
     * @param string $state
     * @param string|null $idToken
     * @param string|null $accessToken
     * @param string|null $tokenType
     * @param int|null $expiresIn
     * @param string|null $code
     * @param string|null $error
     * @param string|null $errorDescription
     * @param string|null $errorUri
     * @return void
     */
    public function __construct(
        private string $state,
        private string|null $idToken = null,
        private string|null $accessToken = null,
        private string|null $tokenType = null,
        private int|null $expiresIn = null,
        private string|null $code = null,
        private string|null $error = null,
        private string|null $errorDescription = null,
        private string|null $errorUri = null
    ) {
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
    public function getIdToken(): string|null
    {
        return $this->idToken;
    }


    /**
     * @return string|null
     */
    public function getAccessToken(): string|null
    {
        return $this->accessToken;
    }


    /**
     * @return string|null
     */
    public function getTokenType(): string|null
    {
        return $this->tokenType;
    }


    /**
     * @return int|null
     */
    public function getExpiresIn(): int|null
    {
        return $this->expiresIn;
    }


    /**
     * @return string|null
     */
    public function getCode(): string|null
    {
        return $this->code;
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
