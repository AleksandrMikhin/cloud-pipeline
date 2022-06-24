package com.epam.lifescience.security.entity.jwt;

import com.epam.lifescience.security.utils.AuthorizationUtils;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.AuthenticationServiceException;

import javax.servlet.http.Cookie;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

@Getter
@EqualsAndHashCode
public class JWTRawToken implements Serializable {

    private final String token;

    @JsonCreator
    public JWTRawToken(@JsonProperty("token") final String token) {
        this.token = token;
    }

    public static JWTRawToken fromHeader(final String authorizationHeader) {
        if (StringUtils.isEmpty(authorizationHeader)) {
            throw new AuthenticationServiceException("Authorization header is blank");
        }
        return getJwtRawToken(authorizationHeader);
    }

    public static JWTRawToken fromCookie(final Cookie authCookie) throws UnsupportedEncodingException {
        if (authCookie == null || StringUtils.isEmpty(authCookie.getValue())) {
            throw new AuthenticationServiceException("Authorization cookie is blank");
        }
        final String authCookieValue = URLDecoder.decode(authCookie.getValue(), "UTF-8");
        return getJwtRawToken(authCookieValue);
    }

    private static JWTRawToken getJwtRawToken(final String authorizationValue) {
        if (authorizationValue.startsWith(AuthorizationUtils.BEARER_PREFIX)) {
            return new JWTRawToken(authorizationValue.substring(AuthorizationUtils.BEARER_PREFIX.length()));
        }

        if (authorizationValue.startsWith(AuthorizationUtils.BASIC_AUTH_PREFIX)) {
            final String[] credentials = AuthorizationUtils.parseBasicAuth(authorizationValue);
            if (credentials != null) {
                return new JWTRawToken(credentials[1]);
            }
        }
        throw new AuthenticationServiceException("Authorization type Bearer or Basic Auth is missed");
    }

    public String toHeader() {
        return AuthorizationUtils.BEARER_PREFIX + token;
    }
}
