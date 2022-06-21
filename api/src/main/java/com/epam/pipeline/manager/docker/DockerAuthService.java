/*
 * Copyright 2017-2019 EPAM Systems, Inc. (https://www.epam.com/)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.epam.pipeline.manager.docker;

import java.time.LocalDateTime;
import java.util.List;

import com.epam.lifescience.security.entity.UserContext;
import com.epam.lifescience.security.entity.jwt.JWTRawToken;
import com.epam.lifescience.security.entity.jwt.JWTTokenClaims;
import com.epam.lifescience.security.exception.jwt.TokenVerificationException;
import com.epam.lifescience.security.jwt.JWTTokenVerifier;
import com.epam.pipeline.common.MessageConstants;
import com.epam.pipeline.common.MessageHelper;
import com.epam.pipeline.exception.docker.DockerAuthorizationException;
import com.epam.pipeline.manager.preference.PreferenceManager;
import com.epam.pipeline.manager.preference.SystemPreferences;
import com.epam.pipeline.manager.user.UserManager;
import com.epam.pipeline.security.jwt.JWTTokenDockerGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.math.NumberUtils;

import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

/**
 * {@code DockerAuthService} provides methods to provide authentication for
 * docker registry
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DockerAuthService {
    private static final int TOKEN_EXPIRATION = 30;

    private final UserManager userManager;
    private final JWTTokenVerifier tokenVerifier;
    private final JWTTokenDockerGenerator tokenDockerGenerator;
    private final PreferenceManager preferenceManager;
    private final MessageHelper messageHelper;

    public JWTRawToken issueDockerToken(final UserContext user, final String service,
                                        final List<DockerRegistryClaim> claims) {
        final Long jwtExpirationSeconds = preferenceManager.getPreference(
                SystemPreferences.DOCKER_SECURITY_TOOL_JWT_TOKEN_EXPIRATION);
        final long expirationTime = jwtExpirationSeconds != null && jwtExpirationSeconds > 0
                ? jwtExpirationSeconds : TOKEN_EXPIRATION;

        Assert.notNull(user, messageHelper.getMessage(MessageConstants.ERROR_DOCKER_REGISTRY_AUTHENTICATION_REQUIRED));
        return new JWTRawToken(tokenDockerGenerator.issueDockerToken(user.toClaims(), expirationTime, service, claims));
    }

    public UserContext verifyTokenForDocker(String userName, String token, String dockerRegistryHost) {
        final UserContext user = userManager.loadUserContext(userName);
        if (user == null) {
            log.debug("Failed to find user by name {}.", userName);
            throw new DockerAuthorizationException(dockerRegistryHost);
        }
        try {
            final JWTTokenClaims tokenClaims = tokenVerifier.readClaims(token);
            if (!tokenClaims.getUserName().equalsIgnoreCase(userName)) {
                log.debug("Provided user and token do not match.");
                throw new DockerAuthorizationException(dockerRegistryHost);
            }
            if (!NumberUtils.isDigits(tokenClaims.getUserId()) ||
                    !user.getUserId().equals(Long.parseLong(tokenClaims.getUserId()))) {
                log.debug("Provided user and token do not match.");
                throw new DockerAuthorizationException(dockerRegistryHost);
            }
            if (tokenClaims.getExpiresAt().isBefore(LocalDateTime.now())) {
                log.debug("Provided token expired ");
                throw new DockerAuthorizationException(dockerRegistryHost);
            }
        } catch (TokenVerificationException e) {
            log.debug(e.getMessage(), e);
            throw new DockerAuthorizationException(dockerRegistryHost);
        }
        return user;
    }
}
