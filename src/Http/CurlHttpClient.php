<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc\Http;

use CodeIgniter\HTTP\CURLRequest;
use Config\Services;

/** HttpClient on top of CodeIgniter's CURLRequest. */
class CurlHttpClient implements HttpClient
{
    /**
     * @param int $timeout Connect and total timeout per request, in seconds
     */
    public function __construct(private readonly int $timeout = 10)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function get(string $url, array $headers = []): array
    {
        $res = $this->client()->get($url, ['headers' => $headers + ['Accept' => 'application/json']]);

        return ['status' => $res->getStatusCode(), 'body' => (string) $res->getBody()];
    }

    /**
     * {@inheritDoc}
     */
    public function post(string $url, array $form, array $headers = []): array
    {
        $res = $this->client()->post($url, [
            'headers'     => $headers + ['Accept' => 'application/json'],
            'form_params' => $form,
        ]);

        return ['status' => $res->getStatusCode(), 'body' => (string) $res->getBody()];
    }

    /**
     * A fresh CURLRequest per call (it keeps options between requests otherwise): TLS
     * verification on, redirects not followed, HTTP errors returned rather than thrown.
     */
    private function client(): CURLRequest
    {
        return Services::curlrequest([
            'timeout'         => $this->timeout,
            'connect_timeout' => $this->timeout,
            'http_errors'     => false,
            'allow_redirects' => false,
            'verify'          => true,
        ], null, null, false);
    }
}
