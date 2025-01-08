<?php

declare(strict_types=1);

namespace Gadget\OAuth\Entity;

class AuthServer implements AuthServerInterface
{
    /**
     * @param string $authUri
     * @param string $tokenUri
     * @param string $jwksUri
     * @param string $clientId
     * @param string $clientSecret
     */
    public function __construct(
        private string $authUri,
        private string $tokenUri,
        private string $jwksUri,
        private string $clientId,
        private string $clientSecret
    ) {
    }


    /**
     * @return string
     */
    public function getAuthUri(): string
    {
        return $this->authUri;
    }


    /**
     * @return string
     */
    public function getTokenUri(): string
    {
        return $this->tokenUri;
    }


    /**
     * @return string
     */
    public function getJwksUri(): string
    {
        return $this->jwksUri;
    }


    /**
     * @return string
     */
    public function getClientId(): string
    {
        return $this->clientId;
    }


    /**
     * @return string
     */
    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }
}
