package com.epam.lifescience.security.jwt;

import com.auth0.jwt.interfaces.Clock;
import com.epam.lifescience.security.TestConstants;
import com.epam.lifescience.security.entity.jwt.JWTTokenClaims;
import com.epam.lifescience.security.exception.jwt.JWTInitializationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;

class JWTTokenGeneratorTest {
    private static final LocalDateTime CURRENT_TEST_DATE = LocalDateTime.of(2022, 4, 27, 11, 20, 10);
    private static final String EXPECTED_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJzdWIiOiJKb2huIERvZSIsIn"
            + "VzZXJfaWQiOiIxMjM0NTY3ODkwIiwicm9sZXMiOlsiUk9MRV9BRE1JTiIsIlJPTEVfVVNFUiJdLCJvcmdfdW5pdF9pZCI6IklU"
            + "IERlcGFydG1lbnQiLCJncm91cHMiOlsiQURNSU5JU1RSQVRPUlMiLCJVU0VSUyJdLCJleHAiOjE2NTEwNDc2NjAsImlhdCI6MT"
            + "Y1MTA0NzYxMCwianRpIjoiMTAifQ.VOCvuMHT7yya2LKDZMPQWXAA1RjL-ZAVxdD1EC_JnCjhANcHU3nISgMQ0XVUn4-W97Fcl"
            + "rp9c6nEZaur2h0pK5vhmggsBJ86-9DIahQnwXSl6KnAgElSS5JIf4lhXXoIVH0g2VZtd4-W8-TKRxRKIbuWeX6FmQUPbM7fFDS"
            + "a44YPXt7fez0_iovdysLFJR7fu96j_J7aF8y3DS2mY-3ElpEEzRXtXH9BYpnhYkyeU_WXCM6l-M4X4weG-4vGNpL_M7Uspr8gB"
            + "BFhdmYakDRCeNVb9Od8lxepG4D2QIddTbZFdceinb2W2dmaUWA8NgEahsvbUhYqAg-ougtotWErqw";

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"SomeWrongPrivateKey", TestConstants.PUBLIC_KEY})
    void shouldThrowIfWrongPublicKey(final String wrongPrivateKey) {
        assertThrows(JWTInitializationException.class,
            () -> new JWTTokenGenerator(wrongPrivateKey, Optional.empty(),Optional.empty()));
    }

    @Test
    void shouldReturnEncodedToken() {
        final Clock clockMock = Mockito.mock(Clock.class);
        Mockito.when(clockMock.getToday()).thenReturn(toDate(CURRENT_TEST_DATE));

        final JWTTokenGenerator jwtTokenGenerator =
                new JWTTokenGenerator(TestConstants.PRIVATE_KEY, Optional.empty(), Optional.of(clockMock));

        final JWTTokenClaims tokenClaims = JWTTokenClaims.builder()
                .jwtTokenId(TestConstants.TOKEN_ID)
                .userId(TestConstants.USER_ID)
                .userName(TestConstants.USER_NAME)
                .orgUnitId(TestConstants.ORG_UNIT_ID)
                .roles(TestConstants.ROLE_LIST)
                .groups(TestConstants.GROUP_LIST)
                .external(false)
                .build();

        Assertions.assertEquals(EXPECTED_TOKEN,
                jwtTokenGenerator.encodeToken(tokenClaims, TestConstants.EXPIRATION_SECONDS));
    }

    private Date toDate(final LocalDateTime dateTime) {
        return Date.from(dateTime.atZone(ZoneId.systemDefault()).toInstant());
    }
}
