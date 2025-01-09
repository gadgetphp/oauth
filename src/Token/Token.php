<?php

declare(strict_types=1);

namespace Gadget\OAuth\Token;

class Token implements TokenInterface
{
    /**
     * @param string $tokenType
     * @param string|null $scope
     * @param int|null $expiresIn
     * @param string|null $accessToken
     * @param IdTokenInterface|null $idToken
     * @param string|null $refreshToken
     * @return void
     */
    public function __construct(
        private string $tokenType,
        private string|null $scope = null,
        private int|null $expiresIn = null,
        private string|null $accessToken = null,
        private IdTokenInterface|null $idToken = null,
        private string|null $refreshToken = null
    ) {
    }


    /**
     * @return string|null
     */
    public function getAccessToken(): string|null
    {
        return $this->accessToken;
    }


    /**
     * @return IdTokenInterface|null
     */
    public function getIdToken(): IdTokenInterface|null
    {
        return $this->idToken;
    }


    /**
     * @return string|null
     */
    public function getRefreshToken(): string|null
    {
        return $this->refreshToken;
    }


    /**
     * @param string|null $refreshToken
     * @return self
     */
    public function setRefreshToken(string|null $refreshToken): self
    {
        $this->refreshToken = $refreshToken;
        return $this;
    }


    /**
     * @return string
     */
    public function getTokenType(): string
    {
        return $this->tokenType;
    }


    /**
     * @param string $tokenType
     * @return self
     */
    public function setTokenType(string $tokenType): self
    {
        $this->tokenType = $tokenType;
        return $this;
    }


    /**
     * @return int
     */
    public function getExpiresIn(): int|null
    {
        return $this->expiresIn;
    }


    /**
     * @param int|null $expiresIn
     * @return self
     */
    public function setExpiresIn(int|null $expiresIn): self
    {
        $this->expiresIn = $expiresIn;
        return $this;
    }


    /**
     * @return string
     */
    public function getScope(): string|null
    {
        return $this->scope;
    }


    /**
     * @param string|null $scope
     * @return self
     */
    public function setScope(string|null $scope): self
    {
        $this->scope = $scope;
        return $this;
    }
}
