<?php

declare(strict_types=1);

namespace Gadget\OAuth\Token;

class TokenValidator implements TokenValidatorInterface
{
    public function validate(TokenInterface $token): bool
    {
        $idTokenValid = ($token->getIdToken()?->getExpirationTime() ?? PHP_INT_MAX) > time();
        $accessTokenValid = $token->getAccessToken() !== null;
        $isNotExpired = ($token->getExpiresIn() ?? PHP_INT_MAX) > time();

        return $isNotExpired && $idTokenValid && $accessTokenValid;
    }
}
