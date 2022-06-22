package com.epam.lifescience.security.jwt;

import com.epam.lifescience.security.entity.jwt.JWTRawToken;
import com.epam.lifescience.security.entity.jwt.JWTTokenClaims;
import com.epam.lifescience.security.service.JWTUserAccessService;
import com.epam.lifescience.security.entity.UserContext;
import com.epam.lifescience.security.exception.jwt.TokenVerificationException;
import com.epam.lifescience.security.utils.AuthorizationUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;

@RequiredArgsConstructor
@Slf4j
public class JWTAuthenticationFilter extends OncePerRequestFilter {
    private final JWTTokenVerifier tokenVerifier;
    private final JWTUserAccessService accessService;

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                    final HttpServletResponse response,
                                    final FilterChain filterChain) throws ServletException, IOException {
        final JWTRawToken rawToken = fetchJwtRawToken(request);
        try {
            if (!StringUtils.isEmpty(rawToken)) {
                final JWTTokenClaims claims = tokenVerifier.readClaims(rawToken.getToken());
                final UserContext context = accessService.getJwtUser(rawToken, claims);
                final JWTAuthenticationToken token = new JWTAuthenticationToken(context);
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(token);
                log.info("Successfully authenticate user with name: " + context.getUsername());
            }
        } catch (TokenVerificationException e) {
            log.info("JWT authentication failed!", e);
        }
        filterChain.doFilter(request, response);
    }

    private JWTRawToken fetchJwtRawToken(final HttpServletRequest request) throws UnsupportedEncodingException {
        JWTRawToken rawToken = null;
        final String authorizationHeader = extractAuthHeader(request);
        final Cookie authCookie = extractAuthCookie(request);
        try {
            if (!StringUtils.isEmpty(authorizationHeader)) { // attempt obtain JWT token from HTTP header
                rawToken = AuthorizationUtils.fromHeader(authorizationHeader);
                log.trace("Extracted JWT token from authorization HTTP header");
            } else if (!StringUtils.isEmpty(authCookie)) {   // else try to get token from cookies
                rawToken = AuthorizationUtils.fromCookie(authCookie);
                log.trace("Extracted JWT token from authorization cookie");
            }
        } catch (AuthenticationServiceException e) {
            log.trace(e.getMessage(), e);
        }
        return rawToken;
    }

    private String extractAuthHeader(final HttpServletRequest request) {
        return request.getHeader(AuthorizationUtils.AUTHORIZATION);
    }

    private Cookie extractAuthCookie(final HttpServletRequest request) {
        return Optional.ofNullable(request.getCookies())
                .map(Arrays::stream)
                .orElseGet(Stream::empty)
                .filter(cookie -> AuthorizationUtils.HTTP_AUTHORIZATION.equals(cookie.getName()))
                .findFirst()
                .orElse(null);
    }
}
