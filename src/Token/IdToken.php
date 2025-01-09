<?php

declare(strict_types=1);

namespace Gadget\OAuth\Token;

use Gadget\Lang\Cast;

class IdToken implements IdTokenInterface
{
    private string $issuer;
    private string $subject;
    private string $audience;
    private int $expirationTime;
    private int $issuedAt;
    private string $nonce;


    /**
     * @param string $idToken
     * @param mixed[] $claims
     */
    public function __construct(
        private string $idToken,
        private array $claims
    ) {
        $cast = new Cast();
        $this->issuer = $cast->toString($claims['iss'] ?? '');
        $this->subject = $cast->toString($claims['sub'] ?? '');
        $this->audience = $cast->toString($claims['aud'] ?? '');
        $this->expirationTime = $cast->toInt($claims['exp'] ?? 0);
        $this->issuedAt = $cast->toInt($claims['iat'] ?? 0);
        $this->nonce = $cast->toString($claims['nonce'] ?? '');
    }


    /**
     * @return string
     */
    public function getIssuer(): string
    {
        return $this->issuer;
    }


    /**
     * @return string
     */
    public function getSubject(): string
    {
        return $this->subject;
    }


    /**
     * @return string
     */
    public function getAudience(): string
    {
        return $this->audience;
    }


    /**
     * @return int
     */
    public function getExpirationTime(): int
    {
        return $this->expirationTime;
    }


    /**
     * @return int
     */
    public function getIssuedAt(): int
    {
        return $this->issuedAt;
    }


    /**
     * @return string
     */
    public function getNonce(): string
    {
        return $this->nonce;
    }


    /**
     * @param string $claim
     * @return bool
     */
    public function hasClaim(string $claim): bool
    {
        return isset($this->claims[$claim]);
    }


    /**
     * @param string $claim
     * @return mixed
     */
    public function getClaim(string $claim): mixed
    {
        return $this->claims[$claim] ?? null;
    }


    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->idToken;
    }
}
