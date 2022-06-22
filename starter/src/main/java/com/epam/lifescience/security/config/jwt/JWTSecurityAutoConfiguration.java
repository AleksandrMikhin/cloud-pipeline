package com.epam.lifescience.security.config.jwt;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Import;

@ConditionalOnProperty(value = "security.config.jwt.enabled", havingValue = "true", matchIfMissing = true)
@Import(JWTSecurityConfiguration.class)
public class JWTSecurityAutoConfiguration {
}
