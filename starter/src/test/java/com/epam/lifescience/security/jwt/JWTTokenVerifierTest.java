package com.epam.lifescience.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.epam.lifescience.security.TestConstants;
import com.epam.lifescience.security.entity.jwt.JWTTokenClaims;
import com.epam.lifescience.security.exception.jwt.JWTInitializationException;
import com.epam.lifescience.security.exception.jwt.TokenVerificationException;
import com.epam.lifescience.security.utils.AuthorizationUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JWTTokenVerifierTest {
    private static final boolean EXTERNAL = true;

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"SomeWrongPublicKey", TestConstants.PRIVATE_KEY})
    void shouldThrowIfWrongPublicKey(final String wrongPublicKey){
        assertThrows(JWTInitializationException.class, () -> new JWTTokenVerifier(wrongPublicKey));
    }

    @Test
    void shouldReturnValidClaims() {
        final Date currentTestDate = new Date();
        final String generatedToken = getTestToken(TestConstants.TOKEN_ID, TestConstants.USER_NAME, currentTestDate);

        final JWTTokenClaims tokenClaims = new JWTTokenVerifier(TestConstants.PUBLIC_KEY).readClaims(generatedToken);
        Assertions.assertAll(
            () -> assertEquals(TestConstants.TOKEN_ID, tokenClaims.getJwtTokenId()),
            () -> assertEquals(TestConstants.USER_ID, tokenClaims.getUserId()),
            () -> assertEquals(TestConstants.USER_NAME, tokenClaims.getUserName()),
            () -> assertEquals(TestConstants.ORG_UNIT_ID, tokenClaims.getOrgUnitId()),
            () -> assertEquals(TestConstants.ROLE_LIST, tokenClaims.getRoles()),
            () -> assertEquals(TestConstants.GROUP_LIST, tokenClaims.getGroups()),
            () -> assertEquals(EXTERNAL, tokenClaims.isExternal())
        );
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t", "\n"})
    void shouldThrowIfWrongToken(final String wrongIdValue) {
        final Date currentTestDate = new Date();
        final String tokenWithWrongTokenId = getTestToken(wrongIdValue, TestConstants.USER_NAME, currentTestDate);
        final String tokenWithWrongUserName = getTestToken(TestConstants.TOKEN_ID, wrongIdValue, currentTestDate);

        assertThrows(TokenVerificationException.class,
            () -> new JWTTokenVerifier(TestConstants.PUBLIC_KEY).readClaims(tokenWithWrongTokenId));

        assertThrows(TokenVerificationException.class,
            () -> new JWTTokenVerifier(TestConstants.PUBLIC_KEY).readClaims(tokenWithWrongUserName));
    }

    @Test
    void shouldThrowIfExpiredToken() {
        final Date expiredTestDate = new Date(0L);
        final String expiredToken = getTestToken(TestConstants.TOKEN_ID, TestConstants.USER_NAME, expiredTestDate);

        final TokenVerificationException verificationException = assertThrows(TokenVerificationException.class,
            () -> new JWTTokenVerifier(TestConstants.PUBLIC_KEY).readClaims(expiredToken));

        Assertions.assertInstanceOf(TokenExpiredException.class, verificationException.getCause());
    }

    private String getTestToken(final String tokenId, final String userName, final Date issueDate) {
        final RSAPrivateKey privateKey;

        try {
            privateKey = (RSAPrivateKey) KeyFactory.getInstance(AuthorizationUtils.RSA_ALGORITHM_NAME)
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(TestConstants.PRIVATE_KEY)));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Something went wrong while generating the test token.", e);
        }

        return JWT.create()
                .withHeader(Collections.singletonMap(AuthorizationUtils.TYP_HEADER_FIELD_NAME,
                        AuthorizationUtils.JWT_TYPE))
                .withJWTId(tokenId)
                .withSubject(userName)
                .withClaim(JWTTokenClaims.CLAIM_USER_ID, TestConstants.USER_ID)
                .withClaim(JWTTokenClaims.CLAIM_ORG_UNIT_ID, TestConstants.ORG_UNIT_ID)
                .withArrayClaim(JWTTokenClaims.CLAIM_GROUPS, TestConstants.GROUP_LIST.toArray(new String[0]))
                .withArrayClaim(JWTTokenClaims.CLAIM_ROLES, TestConstants.ROLE_LIST.toArray(new String[0]))
                .withClaim(JWTTokenClaims.CLAIM_EXTERNAL, EXTERNAL)
                .withIssuedAt(issueDate)
                .withExpiresAt(datePlusSeconds(issueDate, TestConstants.EXPIRATION_SECONDS))
                .sign(Algorithm.RSA512(null, privateKey));
    }

    private Date datePlusSeconds(final Date date, final long seconds) {
        return Date.from(date.toInstant().plusSeconds(seconds));
    }
}
