<?php

declare(strict_types=1);

namespace Gadget\OAuth\Factory;

use Gadget\Lang\Cast;
use Gadget\OAuth\Entity\AuthResponse;
use Gadget\OAuth\Entity\AuthResponseInterface;

class AuthResponseFactory implements AuthResponseFactoryInterface
{
    /**
     * @param mixed $values
     * @return AuthResponseInterface
     */
    public function create(mixed $values): AuthResponseInterface
    {
        $cast = new Cast();
        $values = $cast->toArrayOrNull($values) ?? [];

        return $this->createAuthResponse(
            $cast->toStringOrNull($values['code'] ?? null) ?? '',
            $cast->toStringOrNull($values['state'] ?? null) ?? '',
            $cast->toStringOrNull($values['error'] ?? null),
            $cast->toStringOrNull($values['error_description'] ?? null),
            $cast->toStringOrNull($values['error_uri'] ?? null),
        );
    }


    /**
     * @param string $code
     * @param string $state
     * @param string|null $error
     * @param string|null $errorDescription
     * @param string|null $errorUri
     *
     * @return AuthResponseInterface
     */
    public function createAuthResponse(
        string $code,
        string $state,
        string|null $error = null,
        string|null $errorDescription = null,
        string|null $errorUri = null
    ): AuthResponseInterface {
        return new AuthResponse(
            $code,
            $state,
            $error,
            $errorDescription,
            $errorUri
        );
    }
}
