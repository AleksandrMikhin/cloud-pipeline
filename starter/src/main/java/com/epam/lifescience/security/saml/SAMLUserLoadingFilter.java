package com.epam.lifescience.security.saml;

import com.epam.lifescience.security.entity.UserContext;
import org.springframework.security.saml.SAMLCredential;

/**
 * Components implementing this interface will be used to validate a user in
 * {@link SAMLUserDetailsServiceImpl#loadUserBySAML(SAMLCredential)}
 * use the @Order annotation to determine the priority order of applying filters
 */
public interface SAMLUserLoadingFilter {

    /**
     * In case of invalid/forbidden user context data an exception should be thrown
     *
     * @param context to validate
     */
    void doFilter(UserContext context);

}
