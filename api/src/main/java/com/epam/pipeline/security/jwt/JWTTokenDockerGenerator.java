package com.epam.pipeline.security.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Clock;
import com.epam.lifescience.security.entity.jwt.JWTTokenClaims;
import com.epam.lifescience.security.exception.jwt.JWTInitializationException;
import com.epam.lifescience.security.jwt.JWTTokenExpirationSupplier;
import com.epam.lifescience.security.utils.AuthorizationUtils;
import com.epam.pipeline.manager.docker.DockerRegistryClaim;
import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class JWTTokenDockerGenerator {
    private static final int FINGERPRINT_LENGTH = 30;
    private static final String CLOUD_PIPELINE_ISSUER_NAME = "Cloud pipeline";
    private static final String ACCESS_CLAIM_NAME = "access";
    private static final String ALG_HEADER_FIELD_NAME = "alg";
    private static final String KEY_ID_HEADER_FIELD_NAME = "kid";
    private static final String SHA256_ALGORITHM_NAME = "SHA-256";

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final Clock tokenIssueDateGenerator;
    private final JWTTokenExpirationSupplier tokenExpirationSupplier;

    public JWTTokenDockerGenerator(@Value("${jwt.key.private}") final String privateKeyString,
                                   @Value("${jwt.key.public}")  final String publicKeyString,
                                   @Autowired final Optional<JWTTokenExpirationSupplier> tokenExpirationSupplier,
                                   @Autowired final Optional<Clock> clockBean) {
        if (publicKeyString == null || privateKeyString == null) {
            throw new JWTInitializationException("Public and private keys can't be null");
        }
        try {
            this.privateKey = (RSAPrivateKey) KeyFactory.getInstance(AuthorizationUtils.RSA_ALGORITHM_NAME)
                    .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString)));
            this.publicKey = (RSAPublicKey) KeyFactory.getInstance(AuthorizationUtils.RSA_ALGORITHM_NAME)
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString)));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new JWTInitializationException(e);
        }
        this.tokenIssueDateGenerator = clockBean.orElseGet(() -> Date::new);
        this.tokenExpirationSupplier = tokenExpirationSupplier.orElse(() -> 0);
    }

    /**
     * Generates JWT token for Docker registry authentication according to the documentation:
     * https://docs.docker.com/registry/spec/auth/jwt/#getting-a-bearer-token
     *
     * @param claims               authenticated user
     * @param expirationSeconds    fro token
     * @param service              docker registry id
     * @param dockerRegistryClaims requested changes, may be empty for 'login' requests
     * @return valid JWT token
     */
    public String issueDockerToken(final JWTTokenClaims claims, final Long expirationSeconds, final String service,
                                   final List<DockerRegistryClaim> dockerRegistryClaims) {
        final long expiration = Optional.ofNullable(expirationSeconds)
                .orElseGet(tokenExpirationSupplier::getExpiration);
        final JWTTokenDockerCreator.Builder tokenBuilder = buildDockerToken(claims, service, dockerRegistryClaims);
        tokenBuilder.withExpiresAt(datePlusSeconds(tokenIssueDateGenerator.getToday(), expiration));
        return tokenBuilder.sign(Algorithm.RSA512(null, privateKey));
    }

    private JWTTokenDockerCreator.Builder buildDockerToken(final JWTTokenClaims claims, final String service,
                                                           final List<DockerRegistryClaim> dockerRegistryClaims) {
        final JWTTokenDockerCreator.Builder tokenBuilder = new JWTTokenDockerCreator.Builder();
        final Map<String, Object> header = new HashMap<>();
        header.put(AuthorizationUtils.TYP_HEADER_FIELD_NAME, AuthorizationUtils.JWT_TYPE);
        header.put(ALG_HEADER_FIELD_NAME, publicKey.getAlgorithm());
        header.put(KEY_ID_HEADER_FIELD_NAME, getKeyFingerPrint());
        tokenBuilder
                .withHeader(header)
                .withIssuedAt(tokenIssueDateGenerator.getToday())
                .withJWTId(Strings.isNullOrEmpty(claims.getJwtTokenId()) ?
                        UUID.randomUUID().toString() : claims.getJwtTokenId())
                .withIssuer(CLOUD_PIPELINE_ISSUER_NAME)
                .withAudience(service)
                .withSubject(claims.getUserName());
        if (CollectionUtils.isNotEmpty(dockerRegistryClaims)) {
            tokenBuilder.withObjectClaim(ACCESS_CLAIM_NAME, dockerRegistryClaims);
        }
        return tokenBuilder;
    }

    /*
     * The “kid” field has to be in a libtrust fingerprint compatible format.
     * Such a format can be generated by following steps:
     * Take the DER encoded public key which the JWT token was signed against.
     * Create a SHA256 hash out of it and truncate to 240bits.
     * Split the result into 12 base32 encoded groups with : as delimiter.
     * */
    private String getKeyFingerPrint() {
        try {
            final MessageDigest digest = MessageDigest.getInstance(SHA256_ALGORITHM_NAME);
            final byte[] keyHash = digest.digest(publicKey.getEncoded());
            byte[] truncated = new byte[FINGERPRINT_LENGTH];
            if (keyHash.length > FINGERPRINT_LENGTH) {
                System.arraycopy(keyHash, 0, truncated, 0, FINGERPRINT_LENGTH);
            } else {
                truncated = keyHash;
            }
            final String encoded = BaseEncoding.base32().encode(truncated);
            final StringBuilder result = new StringBuilder();
            for (int i = 0; i < encoded.length(); i++) {
                if (i != 0 && i % 4 == 0) {
                    result.append(':');
                }
                result.append(encoded.charAt(i));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    private Date datePlusSeconds(final Date date, final long seconds) {
        return Date.from(date.toInstant().plusSeconds(seconds));
    }
}
