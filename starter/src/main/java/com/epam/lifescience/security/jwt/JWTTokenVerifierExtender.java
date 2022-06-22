package com.epam.lifescience.security.jwt;

import com.epam.lifescience.security.entity.jwt.JWTExtendedValidationResponse;
import com.epam.lifescience.security.entity.jwt.JWTTokenClaims;

/**
 * A component implementing this interface provides an ability to add additional
 * validation of token claims into {@link JWTTokenVerifier}.
 */
public interface JWTTokenVerifierExtender {
    /**
     * This method should implement a token claims validation.
     *
     * @param tokenClaims claims for verification
     * @return {@link JWTExtendedValidationResponse}
     */
    JWTExtendedValidationResponse validateClaims(JWTTokenClaims tokenClaims);
}
