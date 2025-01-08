<?php

declare(strict_types=1);

namespace Gadget\OAuth\Entity;

class Pkce implements PkceInterface
{
    /**
     * @param string $codeVerifier
     * @param string $codeChallenge
     * @param string $codeChallengeMethod
     */
    public function __construct(
        private string $codeVerifier,
        private string $codeChallenge,
        private string $codeChallengeMethod
    ) {
    }


    /**
     * @return string
     */
    public function getCodeVerifier(): string
    {
        return $this->codeVerifier;
    }


    /**
     * @return string
     */
    public function getCodeChallenge(): string
    {
        return $this->codeChallenge;
    }


    /**
     * @return string
     */
    public function getCodeChallengeMethod(): string
    {
        return $this->codeChallengeMethod;
    }
}
