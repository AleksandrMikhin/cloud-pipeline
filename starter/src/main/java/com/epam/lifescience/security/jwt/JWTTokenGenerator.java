package com.epam.lifescience.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Clock;
import com.epam.lifescience.security.entity.jwt.JWTTokenClaims;
import com.epam.lifescience.security.exception.jwt.JWTInitializationException;
import com.epam.lifescience.security.utils.AuthorizationUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
public class JWTTokenGenerator {
    private final RSAPrivateKey privateKey;
    private final Clock tokenIssueDateGenerator;
    private final JWTTokenExpirationSupplier tokenExpirationSupplier;

    public JWTTokenGenerator(@Value("${jwt.key.private}") final String privateKeyString,
                             @Autowired final Optional<JWTTokenExpirationSupplier> tokenExpirationSupplier,
                             @Autowired final Optional<Clock> clockBean) {
        Optional.ofNullable(privateKeyString)
                .orElseThrow(() -> new JWTInitializationException("Private key can't be null"));

        this.tokenIssueDateGenerator = clockBean.orElseGet(() -> Date::new);
        this.tokenExpirationSupplier = tokenExpirationSupplier.orElse(() -> 0);
        try {
            this.privateKey = (RSAPrivateKey) KeyFactory.getInstance(AuthorizationUtils.RSA_ALGORITHM_NAME)
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new JWTInitializationException(e);
        }
    }

    public String encodeToken(final JWTTokenClaims claims, final Long expirationSeconds) {
        final long expiration = Optional.ofNullable(expirationSeconds)
                .orElseGet(tokenExpirationSupplier::getExpiration);
        final Date todayDate = tokenIssueDateGenerator.getToday();
        return buildToken(claims)
                .withIssuedAt(todayDate)
                .withExpiresAt(datePlusSeconds(todayDate, expiration))
                .sign(Algorithm.RSA512(null, privateKey));
    }

    private JWTCreator.Builder buildToken(final JWTTokenClaims claims) {
        final JWTCreator.Builder tokenBuilder =
                JWT.create()
                        .withHeader(Collections.singletonMap(AuthorizationUtils.TYP_HEADER_FIELD_NAME,
                                AuthorizationUtils.JWT_TYPE))
                        .withJWTId(StringUtils.isBlank(claims.getJwtTokenId()) ?
                                UUID.randomUUID().toString() : claims.getJwtTokenId())
                        .withSubject(claims.getUserName())
                        .withClaim(JWTTokenClaims.CLAIM_USER_ID, claims.getUserId())
                        .withClaim(JWTTokenClaims.CLAIM_ORG_UNIT_ID, claims.getOrgUnitId())
                        .withArrayClaim(JWTTokenClaims.CLAIM_GROUPS, claims.getGroups().toArray(new String[0]))
                        .withArrayClaim(JWTTokenClaims.CLAIM_ROLES, claims.getRoles().toArray(new String[0]));

        if (claims.isExternal()) {
            tokenBuilder.withClaim(JWTTokenClaims.CLAIM_EXTERNAL, claims.isExternal());
        }

        return tokenBuilder;
    }

    private Date datePlusSeconds(final Date date, final long seconds) {
        return Date.from(date.toInstant().plusSeconds(seconds));
    }
}
