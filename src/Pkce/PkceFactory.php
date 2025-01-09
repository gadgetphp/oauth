<?php

declare(strict_types=1);

namespace Gadget\OAuth\Pkce;

use Gadget\Lang\Cast;

class PkceFactory implements PkceFactoryInterface
{
    /** @var string */
    private const VERIFIER_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';


    /**
     * @param mixed $values
     * @return PkceInterface
     */
    public function create(mixed $values): PkceInterface
    {
        $cast = new Cast();
        $values = $cast->toArrayOrNull($values) ?? [];

        return $this->createPkce(
            $cast->toStringOrNull($values['method'] ?? null) ?? 'S256'
        );
    }


    /**
     * @param string $method
     * @return PkceInterface
     */
    public function createPkce(string $method = 'S256'): PkceInterface
    {
        $size = random_int(43, 128);
        /** @var int[]|false $bytes */
        $bytes = unpack("C{$size}", random_bytes($size));

        $verifier = join(
            array_map(
                fn (int $v): string => substr(
                    self::VERIFIER_CHARS,
                    $v % strlen(self::VERIFIER_CHARS),
                    1
                ),
                is_array($bytes)
                    ? $bytes
                    : throw new \Random\RandomError("Unable to generate random number to use in PKCE verifier")
            )
        );
        $challenge = match ($method) {
            'S256' => base64_encode(hash('SHA256', $verifier, true)),
            'plain' => $verifier,
            default => throw new \RuntimeException()
        };

        return new Pkce(
            $verifier,
            $challenge,
            $method
        );
    }
}
