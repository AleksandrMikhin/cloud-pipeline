package com.epam.lifescience.security.config.saml;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Import;

@ConditionalOnProperty(value = "security.config.saml.enabled", havingValue = "true", matchIfMissing = true)
@Import(SAMLSecurityConfiguration.class)
public class SAMLSecurityAutoConfiguration {
}
