package com.epam.lifescience.security.utils;

import com.epam.lifescience.security.entity.jwt.JWTRawToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.AuthenticationServiceException;

import javax.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthorizationUtilsTest {
    public static final String SOME_BASIC_AUTH_HEADER = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==";
    public static final String FIRST_CREDENTIAL = "Aladdin";
    public static final String SECOND_CREDENTIAL = "open sesame";

    public static final String BASIC_AUTH_PREFIX = "Basic ";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String SOME_AUTH_TOKEN = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJQSVBFX0";
    public static final String BEARER_AUTH_HEADER = BEARER_PREFIX + SOME_AUTH_TOKEN;

    @Test
    void shouldReturnNullDuringParseNullAuth() {
        assertNull(AuthorizationUtils.parseBasicAuth(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "some string", ":", "only name:", ":only password"})
    void shouldReturnNullDuringParseWrongAuth(final String credentials) {
        final String authorization = BASIC_AUTH_PREFIX
                + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        assertNull(AuthorizationUtils.parseBasicAuth(authorization));
    }

    @Test
    void shouldReturnCorrectValuesDuringParseAuth() {
        final String[] credentials = AuthorizationUtils.parseBasicAuth(SOME_BASIC_AUTH_HEADER);
        assertEquals(2, credentials.length);
        assertAll(
            () -> assertEquals(FIRST_CREDENTIAL, credentials[0]),
            () -> assertEquals(SECOND_CREDENTIAL, credentials[1])
        );
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"some string"})
    void shouldThrowIfWrongAuthorizationHeader(final String authorizationHeader) {
        assertThrows(AuthenticationServiceException.class, () -> AuthorizationUtils.fromHeader(authorizationHeader));
    }

    @Test
    void shouldReturnRawTokenFromBearerAuthHeader() {
        final JWTRawToken jwtRawToken = AuthorizationUtils.fromHeader(BEARER_AUTH_HEADER);
        assertEquals(SOME_AUTH_TOKEN, jwtRawToken.getToken());
    }

    @Test
    void shouldReturnRawTokenFromBasicAuthHeader() {
        final JWTRawToken jwtRawToken = AuthorizationUtils.fromHeader(SOME_BASIC_AUTH_HEADER);
        assertEquals(SECOND_CREDENTIAL, jwtRawToken.getToken());
    }

    @Test
    void shouldReturnRawTokenFromCookie() {
        final Cookie authCookie = new Cookie("someCookie", SOME_BASIC_AUTH_HEADER);
        final JWTRawToken jwtRawToken = assertDoesNotThrow(() -> AuthorizationUtils.fromCookie(authCookie));
        assertEquals(SECOND_CREDENTIAL, jwtRawToken.getToken());
    }

    @ParameterizedTest
    @MethodSource("provideWrongCasesForJwtTokenCreationFromCookie")
    void shouldThrowIfWrongCookie(final Cookie authCookie) {
        assertThrows(AuthenticationServiceException.class, () -> AuthorizationUtils.fromCookie(authCookie));
    }

    static Stream<Arguments> provideWrongCasesForJwtTokenCreationFromCookie() {
        return Stream.of(
                        null,
                        new Cookie("emptyCookie", ""),
                        new Cookie("wrongCookie", "someWrongString"))
                .map(Arguments::of);
    }
}
