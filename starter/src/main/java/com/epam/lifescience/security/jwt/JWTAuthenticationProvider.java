package com.epam.lifescience.security.jwt;

import com.epam.lifescience.security.entity.jwt.JWTRawToken;
import com.epam.lifescience.security.entity.jwt.JWTTokenClaims;
import com.epam.lifescience.security.service.JWTUserAccessService;
import com.epam.lifescience.security.entity.UserContext;
import com.epam.lifescience.security.exception.jwt.TokenVerificationException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;

@RequiredArgsConstructor
public class JWTAuthenticationProvider implements AuthenticationProvider {
    private final JWTTokenVerifier tokenVerifier;
    private final JWTUserAccessService accessService;

    @Override
    public Authentication authenticate(final Authentication authentication) {
        final JWTRawToken jwtRawToken = (JWTRawToken) authentication.getCredentials();
        if (jwtRawToken == null) {
            throw new AuthenticationServiceException("Authentication error: missing token");
        }
        final JWTTokenClaims claims;
        try {
            claims = tokenVerifier.readClaims(jwtRawToken.getToken());
        } catch (TokenVerificationException e) {
            throw new AuthenticationServiceException("Authentication error", e);
        }

        final UserContext context = accessService.getJwtUser(jwtRawToken, claims);
        return new JWTAuthenticationToken(context);
    }

    @Override
    public boolean supports(final Class<?> authentication) {
        return (JWTAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
