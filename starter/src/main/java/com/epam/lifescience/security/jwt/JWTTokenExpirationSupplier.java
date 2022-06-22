package com.epam.lifescience.security.jwt;

/**
 * A component implementing this interface provides a default token expiration
 * time for creating a new token into {@link JWTTokenGenerator}.
 */
public interface JWTTokenExpirationSupplier {

    long getExpiration();

}
