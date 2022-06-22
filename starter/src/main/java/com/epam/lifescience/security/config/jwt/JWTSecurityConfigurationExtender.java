package com.epam.lifescience.security.config.jwt;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * A component implementing this interface provides an ability to add extra settings
 * web based security for specific http requests into {@link JWTSecurityConfiguration}.
 */
public interface JWTSecurityConfigurationExtender {

    void configure(HttpSecurity http) throws Exception;

}
