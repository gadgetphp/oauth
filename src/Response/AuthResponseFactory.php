<?php

declare(strict_types=1);

namespace Gadget\OAuth\Response;

use Gadget\Lang\Cast;

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

        return isset($values['id_token'])
            ? $this->createImplicitFlowResponse(
                $cast->toString($values['state'] ?? ''),
                $cast->toString($values['id_token']),
                $cast->toStringOrNull($values['token_type'] ?? null),
                $cast->toStringOrNull($values['access_token'] ?? null),
                $cast->toIntOrNull($values['expires_in'] ?? null),
                $cast->toStringOrNull($values['error'] ?? null),
                $cast->toStringOrNull($values['error_description'] ?? null),
                $cast->toStringOrNull($values['error_uri'] ?? null),
            )
            : $this->createAuthCodeResponse(
                $cast->toString($values['state'] ?? ''),
                $cast->toString($values['code'] ?? ''),
                $cast->toStringOrNull($values['error'] ?? null),
                $cast->toStringOrNull($values['error_description'] ?? null),
                $cast->toStringOrNull($values['error_uri'] ?? null),
            );
    }


    /**
     * @param string $state
     * @param string $code
     * @param string|null $error
     * @param string|null $errorDescription
     * @param string|null $errorUri
     *
     * @return AuthResponseInterface
     */
    public function createAuthCodeResponse(
        string $state,
        string $code,
        string|null $error = null,
        string|null $errorDescription = null,
        string|null $errorUri = null
    ): AuthResponseInterface {
        return new AuthCodeResponse(
            $state,
            $code,
            $error,
            $errorDescription,
            $errorUri
        );
    }


    /**
     * @param string $state
     * @param string $idToken
     * @param string|null $tokenType
     * @param string|null $accessToken
     * @param int|null $expiresIn
     * @param string|null $error
     * @param string|null $errorDescription
     * @param string|null $errorUri
     *
     * @return AuthResponseInterface
     */
    public function createImplicitFlowResponse(
        string $state,
        string $idToken,
        string|null $tokenType = null,
        string|null $accessToken = null,
        int|null $expiresIn = null,
        string|null $error = null,
        string|null $errorDescription = null,
        string|null $errorUri = null
    ): AuthResponseInterface {
        return new ImplicitFlowResponse(
            $state,
            $idToken,
            $accessToken,
            $tokenType,
            $expiresIn,
            $error,
            $errorDescription,
            $errorUri
        );
    }
}
