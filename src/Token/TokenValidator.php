<?php

declare(strict_types=1);

namespace Gadget\OAuth\Token;

class TokenValidator
{
    public function validate(TokenInterface $token): bool
    {
        return true;
    }
}
