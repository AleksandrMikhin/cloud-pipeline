package com.epam.lifescience.security.config.saml;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * A component implementing this interface provides an ability to add extra settings
 * web based security for specific http requests into {@link SAMLSecurityConfiguration}.
 */
public interface SAMLSecurityConfigurationExtender {

    void configure(HttpSecurity http) throws Exception;

}
