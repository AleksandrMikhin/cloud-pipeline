package com.epam.lifescience.security.exception.jwt;

public class TokenVerificationException extends RuntimeException {
    public TokenVerificationException(final String message) {
        super(message);
    }

    public TokenVerificationException(final Throwable cause) {
        super(cause);
    }

    public TokenVerificationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
