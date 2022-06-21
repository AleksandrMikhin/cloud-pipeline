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

package com.epam.pipeline.app;

import com.epam.lifescience.security.config.jwt.JWTSecurityConfigurationExtender;
import com.epam.lifescience.security.config.saml.SAMLSecurityConfigurationExtender;
import com.epam.lifescience.security.jwt.JWTTokenExpirationSupplier;
import com.epam.lifescience.security.utils.ConfigUtils;
import com.epam.pipeline.entity.user.DefaultRoles;
import com.epam.pipeline.manager.preference.PreferenceManager;
import com.epam.pipeline.manager.preference.SystemPreferences;
import com.epam.pipeline.manager.user.ImpersonateFailureHandler;
import com.epam.pipeline.manager.user.ImpersonateSuccessHandler;
import com.epam.pipeline.manager.user.ImpersonationManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Import({AclSecurityConfiguration.class,
        ProxySecurityConfig.class})
public class SecurityConfig {

    @Value("${api.security.anonymous.urls:/restapi/route}")
    private String[] anonymousResources;

    @Value("${api.security.impersonation.operations.root.url:/restapi/user/impersonation}")
    private String impersonationOperationsRootUrl;

    @Autowired
    private PreferenceManager preferenceManager;

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurerAdapter() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping(ConfigUtils.ANY_URL_PATTERN)
                        .allowedOrigins(getCorsAllowedOrigins())
                        .allowedMethods("*")
                        .allowedHeaders("*");
            }
        };
    }

    @Bean
    public JWTSecurityConfigurationExtender jwtSecurityConfigurationExtender() {
        return http -> http.authorizeRequests()
                .antMatchers(anonymousResources).hasAnyAuthority(DefaultRoles.ROLE_ADMIN.getName(),
                        DefaultRoles.ROLE_USER.getName(), DefaultRoles.ROLE_ANONYMOUS_USER.getName())
                .antMatchers(getImpersonationStartUrl()).hasAuthority(DefaultRoles.ROLE_ADMIN.getName());
    }

    @Bean
    public JWTTokenExpirationSupplier jwtTokenExpirationSupplier() {
        return () -> preferenceManager.getPreference(SystemPreferences.LAUNCH_JWT_TOKEN_EXPIRATION);
    }

    @Bean
    public SAMLSecurityConfigurationExtender samlSecurityConfigurationExtender() {
        return http -> http.authorizeRequests()
                .antMatchers(anonymousResources).hasAnyAuthority(DefaultRoles.ROLE_ADMIN.getName(),
                        DefaultRoles.ROLE_USER.getName(), DefaultRoles.ROLE_ANONYMOUS_USER.getName())
                .antMatchers(getImpersonationStartUrl()).hasAuthority(DefaultRoles.ROLE_ADMIN.getName());
    }

    @Bean
    public SwitchUserFilter switchUserFilter(final ImpersonationManager impersonationManager) {
        final SwitchUserFilter filter = new SwitchUserFilter();
        filter.setUserDetailsService(impersonationManager);
        filter.setUserDetailsChecker(impersonationManager);
        filter.setSwitchUserUrl(getImpersonationStartUrl());
        filter.setExitUserUrl(getImpersonationStopUrl());
        filter.setFailureHandler(new ImpersonateFailureHandler(getImpersonationStartUrl(), getImpersonationStopUrl()));
        filter.setSuccessHandler(new ImpersonateSuccessHandler(getImpersonationStartUrl(), getImpersonationStopUrl()));
        return filter;
    }

    protected String getImpersonationStartUrl() {
        return impersonationOperationsRootUrl + "/start";
    }

    protected String getImpersonationStopUrl() {
        return impersonationOperationsRootUrl + "/stop";
    }

    protected String[] getCorsAllowedOrigins() {
        return new String[]{"*"};
    }
}
