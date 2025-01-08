<?php

declare(strict_types=1);

namespace Gadget\OAuth\Entity;

class AuthRequest implements AuthRequestInterface
{
    /**
     * @param AuthServerInterface $authServer
     * @param string $redirectUri
     * @param string|null $scope
     * @param string $state
     * @param PkceInterface|null $pkce
     * @param string|null $responseMode
     * @param string|null $nonce
     * @param string|null $display
     * @param string|null $prompt
     * @param int|null $maxAge
     * @param string|null $uiLocales
     * @param string|null $idTokenHint
     * @param string|null $loginTokenHint
     */
    public function __construct(
        private AuthServerInterface $authServer,
        private string $redirectUri,
        private string|null $scope,
        private string $state,
        private PkceInterface|null $pkce = null,
        private string|null $responseMode = null,
        private string|null $nonce = null,
        private string|null $display = null,
        private string|null $prompt = null,
        private int|null $maxAge = null,
        private string|null $uiLocales = null,
        private string|null $idTokenHint = null,
        private string|null $loginTokenHint = null
    ) {
    }


    /**
     * @return AuthServerInterface
     */
    public function getAuthServer(): AuthServerInterface
    {
        return $this->authServer;
    }


    /**
     * @return string
     */
    public function getResponseType(): string
    {
        return 'code';
    }


    /**
     * @return string
     */
    public function getRedirectUri(): string
    {
        return $this->redirectUri;
    }


    /**
     * @return string
     */
    public function getScope(): string|null
    {
        return $this->scope;
    }


    /**
     * @return string
     */
    public function getState(): string
    {
        return $this->state;
    }


    /**
     * @return PkceInterface|null
     */
    public function getPkce(): PkceInterface|null
    {
        return $this->pkce;
    }


    /**
     * @return string|null
     */
    public function getResponseMode(): string|null
    {
        return $this->responseMode;
    }


    /**
     * @return string|null
     */
    public function getNonce(): string|null
    {
        return $this->nonce;
    }


    /**
     * @return string|null
     */
    public function getDisplay(): string|null
    {
        return $this->display;
    }


    /**
     * @return string
     */
    public function getPrompt(): string|null
    {
        return $this->prompt;
    }


    /**
     * @return int|null
     */
    public function getMaxAge(): int|null
    {
        return $this->maxAge;
    }


    /**
     * @return string|null
     */
    public function getUiLocales(): string|null
    {
        return $this->uiLocales;
    }


    /**
     * @return string|null
     */
    public function getIdTokenHint(): string|null
    {
        return $this->idTokenHint;
    }


    /**
     * @return string|null
     */
    public function getLoginTokenHint(): string|null
    {
        return $this->loginTokenHint;
    }


    /**
     * @return string
     */
    public function getUri(): string
    {
        return sprintf(
            "%s?%s",
            $this->getAuthServer()->getAuthUri(),
            http_build_query([
                'redirect_uri' => $this->getRedirectUri(),
                'scope' => $this->getScope(),
                'state' => $this->getState(),
                'code_challenge' => $this->getPkce()?->getCodeChallenge() ?? null,
                'code_challenge_method' => $this->getPkce()?->getCodeChallengeMethod() ?? null,
                'response_mode' => $this->getResponseMode(),
                'nonce' => $this->getNonce(),
                'display' => $this->getDisplay(),
                'prompt' => $this->getPrompt(),
                'max_age' => $this->getMaxAge(),
                'ui_locales' => $this->getUiLocales(),
                'id_token_hint' => $this->getIdTokenHint(),
                'login_token_hint' => $this->getLoginTokenHint()
            ], "", null, PHP_QUERY_RFC3986)
        );
    }
}
