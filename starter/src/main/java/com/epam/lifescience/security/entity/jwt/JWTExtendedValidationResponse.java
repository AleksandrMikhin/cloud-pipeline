package com.epam.lifescience.security.entity.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * This class contains a validation response of token claims.
 */
@AllArgsConstructor
@Getter
public class JWTExtendedValidationResponse {
    /**
     * Status of validation.
     */
    private final boolean isValid;
    /**
     * Details of validation.
     */
    private final String message;
}
