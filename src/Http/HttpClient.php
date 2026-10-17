<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc\Http;

/**
 * The few HTTP calls a relying party makes: discovery, JWKS, token and userinfo.
 * Swap in your own (proxy, mTLS, logging) by setting ShieldOidc::$httpClient.
 */
interface HttpClient
{
    /**
     * @param array<string, string> $headers
     *
     * @return array{status: int, body: string}
     */
    public function get(string $url, array $headers = []): array;

    /**
     * Form-encoded POST.
     *
     * @param array<string, string> $form
     * @param array<string, string> $headers
     *
     * @return array{status: int, body: string}
     */
    public function post(string $url, array $form, array $headers = []): array;
}
