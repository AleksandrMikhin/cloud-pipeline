package com.epam.lifescience.security.jwt;

import com.epam.lifescience.security.entity.jwt.JWTRawToken;
import com.epam.lifescience.security.entity.UserContext;
import org.joda.time.DateTime;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Date;
import java.util.Optional;

public class JWTAuthenticationToken extends AbstractAuthenticationToken {
    private static final int TOKEN_SESSION_TIMEOUT = 60;
    private final Date tokenExpiration;
    private JWTRawToken jwtRawToken;
    private UserContext userContext;

    public JWTAuthenticationToken(final JWTRawToken jwtRawToken) {
        super(null);
        this.jwtRawToken = jwtRawToken;
        this.setAuthenticated(false);
        this.tokenExpiration = DateTime.now().plusSeconds(TOKEN_SESSION_TIMEOUT).toDate();
    }

    public JWTAuthenticationToken(final UserContext userContext) {
        this(userContext, userContext.getAuthorities());
    }

    public JWTAuthenticationToken(final UserContext userContext,
                                  final Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        super.setAuthenticated(true);
        this.userContext = userContext;
        this.tokenExpiration = DateTime.now().plusSeconds(TOKEN_SESSION_TIMEOUT).toDate();
    }

    @Override
    public void setAuthenticated(final boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
    }

    @Override
    public boolean isAuthenticated() {
        return Optional.ofNullable(tokenExpiration).map(token -> new Date().compareTo(token) < 0)
                .orElseGet(super::isAuthenticated);
    }

    @Override
    public Object getCredentials() {
        return this.jwtRawToken;
    }

    @Override
    public Object getPrincipal() {
        return this.userContext;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.jwtRawToken = null;
    }
}
