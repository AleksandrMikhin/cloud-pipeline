package com.epam.lifescience.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.epam.lifescience.security.entity.jwt.JWTTokenClaims;
import com.epam.lifescience.security.exception.jwt.JWTInitializationException;
import com.epam.lifescience.security.exception.jwt.TokenVerificationException;
import com.epam.lifescience.security.utils.AuthorizationUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

public class JWTTokenVerifier {
    private final RSAPublicKey publicKey;

    @Autowired(required = false)
    private JWTTokenVerifierExtender tokenVerifierExtender;

    public JWTTokenVerifier(final String publicKey) {
        Optional.ofNullable(publicKey)
                .orElseThrow(() -> new JWTInitializationException("Public key can't be null"));
        try {
            this.publicKey = (RSAPublicKey) KeyFactory.getInstance(AuthorizationUtils.RSA_ALGORITHM_NAME)
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new JWTInitializationException(e);
        }
    }

    public JWTTokenClaims readClaims(final String jwtToken) {
        final DecodedJWT decodedToken;

        try {
            decodedToken = JWT.require(Algorithm.RSA512(publicKey, null))
                    .build()
                    .verify(jwtToken);

        } catch (JWTVerificationException jve) {
            throw new TokenVerificationException(jve);
        }

        final JWTTokenClaims tokenClaims = JWTTokenClaims.builder()
                .jwtTokenId(decodedToken.getId())
                .userName(decodedToken.getSubject())
                .userId(decodedToken.getClaim(JWTTokenClaims.CLAIM_USER_ID).asString())
                .orgUnitId(decodedToken.getClaim(JWTTokenClaims.CLAIM_ORG_UNIT_ID).asString())
                .roles(Arrays.asList(decodedToken.getClaim(JWTTokenClaims.CLAIM_ROLES).asArray(String.class)))
                .groups(Arrays.asList(decodedToken.getClaim(JWTTokenClaims.CLAIM_GROUPS).asArray(String.class)))
                .issuedAt(decodedToken.getIssuedAt().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime())
                .expiresAt(decodedToken.getExpiresAt().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime())
                .external(!decodedToken.getClaim(JWTTokenClaims.CLAIM_EXTERNAL).isNull() &&
                        decodedToken.getClaim(JWTTokenClaims.CLAIM_EXTERNAL).asBoolean())
                .build();

        return validateClaims(tokenClaims);
    }

    private JWTTokenClaims validateClaims(final JWTTokenClaims tokenClaims) {
        if (StringUtils.isBlank(tokenClaims.getJwtTokenId())) {
            throw new TokenVerificationException("Invalid token: token ID is empty");
        }

        if (StringUtils.isBlank(tokenClaims.getUserName())) {
            throw new TokenVerificationException("Invalid token: user name is empty");
        }

        Optional.ofNullable(tokenVerifierExtender)
                .map(verifier -> verifier.validateClaims(tokenClaims))
                .filter(validateResponse -> !validateResponse.isValid())
                .ifPresent(validateResponse -> {
                    throw new TokenVerificationException(validateResponse.getMessage());
                });

        return tokenClaims;
    }
}
