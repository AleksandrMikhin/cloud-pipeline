package com.epam.lifescience.security.exception.jwt;

public class JWTInitializationException extends RuntimeException {
    public JWTInitializationException(final String message) {
        super(message);
    }

    public JWTInitializationException(final Throwable cause) {
        super(cause);
    }
}
