<?php

declare(strict_types=1);

namespace Gadget\OAuth\Factory;

use Gadget\Lang\Cast;
use Gadget\OAuth\Entity\AuthServer;
use Gadget\OAuth\Entity\AuthServerInterface;

class AuthServerFactory implements AuthServerFactoryInterface
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
     * @param mixed $values
     * @return AuthServerInterface
     */
    public function create(mixed $values): AuthServerInterface
    {
        $cast = new Cast();
        $values = $cast->toArrayOrNull($values) ?? [];

        return $this->createAuthServer(
            $cast->toStringOrNull($values['authUri'] ?? null),
            $cast->toStringOrNull($values['tokenUri'] ?? null),
            $cast->toStringOrNull($values['jwksUri'] ?? null),
            $cast->toStringOrNull($values['clientId'] ?? null),
            $cast->toStringOrNull($values['clientSecret'] ?? null),
        );
    }


    /**
     * @param string|null $authUri
     * @param string|null $tokenUri
     * @param string|null $jwksUri
     * @param string|null $clientId
     * @param string|null $clientSecret
     */
    public function createAuthServer(
        string|null $authUri = null,
        string|null $tokenUri = null,
        string|null $jwksUri = null,
        string|null $clientId = null,
        string|null $clientSecret = null
    ): AuthServerInterface {
        return new AuthServer(
            $authUri ?? $this->authUri,
            $tokenUri ?? $this->tokenUri,
            $jwksUri ?? $this->jwksUri,
            $clientId ?? $this->clientId,
            $clientSecret ?? $this->clientSecret
        );
    }
}
