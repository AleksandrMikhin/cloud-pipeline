package com.epam.lifescience.security.utils;

import com.epam.lifescience.security.entity.jwt.JWTRawToken;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.AuthenticationServiceException;

import javax.servlet.http.Cookie;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@SuppressWarnings("checkstyle:HideUtilityClassConstructor")
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class AuthorizationUtils {
    public static final String AUTHORIZATION = "Authorization";
    public static final String HTTP_AUTHORIZATION = "HttpAuthorization";
    public static final String BASIC_AUTH_PREFIX = "Basic ";
    public static final String BEARER_PREFIX = "Bearer ";

    public static final String TYP_HEADER_FIELD_NAME = "typ";
    public static final String JWT_TYPE = "JWT";
    public static final String RSA_ALGORITHM_NAME = "RSA";

    public static String[] parseBasicAuth(final String authorization) {
        if (authorization != null && authorization.startsWith(BASIC_AUTH_PREFIX)) {
            // Authorization: Basic base64credentials
            final String base64Credentials = authorization.substring(BASIC_AUTH_PREFIX.length()).trim();
            final String credentials = new String(Base64.getDecoder().decode(base64Credentials),
                    StandardCharsets.UTF_8);
            // credentials = username:password
            final String[] values = credentials.split(":", 2);
            if (values.length == 2 && StringUtils.isNotBlank(values[0]) && StringUtils.isNotBlank(values[1])) {
                return values;
            }
        }
        return null;
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

        return getJwtRawToken(URLDecoder.decode(authCookie.getValue(), StandardCharsets.UTF_8.name()));
    }

    private static JWTRawToken getJwtRawToken(final String authorizationValue) {
        if (authorizationValue.startsWith(BEARER_PREFIX)) {
            return new JWTRawToken(authorizationValue.substring(BEARER_PREFIX.length()));
        }

        if (authorizationValue.startsWith(AuthorizationUtils.BASIC_AUTH_PREFIX)) {
            final String[] credentials = parseBasicAuth(authorizationValue);
            if (credentials != null) {
                return new JWTRawToken(credentials[1]);
            }
        }

        throw new AuthenticationServiceException("Authorization type Bearer or Basic Auth is missed");
    }
}
