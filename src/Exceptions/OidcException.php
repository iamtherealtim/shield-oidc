<?php

declare(strict_types=1);

namespace DaemonLabs\ShieldOidc\Exceptions;

use RuntimeException;
use Throwable;

/**
 * Anything that stops a sign-in. The message is safe to show to the person signing in; the
 * detail (if any) is for the log only and may name endpoints, claims or provider errors.
 */
class OidcException extends RuntimeException
{
    /**
     * @param string $message Shown to the person signing in; keep it free of internals
     * @param string $detail  Written to the log: what actually went wrong
     */
    public function __construct(string $message, private readonly string $detail = '', ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }

    /**
     * The log detail, or the message when there is none.
     */
    public function getDetail(): string
    {
        return $this->detail !== '' ? $this->detail : $this->getMessage();
    }

    /** A sign-in problem caused by the token or the provider's response. */
    public static function token(string $detail): self
    {
        return new self(lang('Oidc.tokenInvalid'), $detail);
    }

    /** A setup problem the developer has to fix (bad config, unreachable provider). */
    public static function config(string $detail, ?Throwable $previous = null): self
    {
        return new self(lang('Oidc.providerUnavailable'), $detail, $previous);
    }
}
