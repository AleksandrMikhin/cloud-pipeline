package com.epam.lifescience.security.config.jwt;

import com.epam.lifescience.security.service.JWTUserAccessService;
import com.epam.lifescience.security.jwt.JWTAuthenticationProvider;
import com.epam.lifescience.security.jwt.JWTAuthenticationFilter;
import com.epam.lifescience.security.jwt.JWTTokenVerifier;
import com.epam.lifescience.security.jwt.RestAuthenticationEntryPoint;
import com.epam.lifescience.security.utils.ConfigUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static com.epam.lifescience.security.utils.ConfigUtils.getRequestMatcher;
import static com.epam.lifescience.security.utils.ConfigUtils.isNotBlankStringArray;

@Configuration
@ComponentScan(basePackages = "com.epam.lifescience.security.jwt")
@Order(1)
public class JWTSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Value("${jwt.key.public}")
    private String publicKey;

    @Value("${jwt.disable.session:true}")
    private boolean disableJwtSession;

    @Value("${server.error.path:/error}")
    private String errorControllerPath;

    @Value("${security.config.jwt.secured.urls:/restapi/**}")
    private String[] securedUrls;

    @Value("${security.config.public.urls:}")
    private String[] publicUrls;

    //List of urls under REST that should be redirected back after authorization
    @Value("${security.config.jwt.redirected.urls:}")
    private String[] redirectedUrls;

    @Value("${security.config.authorities.with.secured.urls.access:}")
    private String[] authoritiesWithSecuredAccess;

    @Autowired(required = false)
    private SAMLAuthenticationProvider samlAuthenticationProvider;

    @Autowired(required = false)
    private SAMLEntryPoint samlEntryPoint;

    @Autowired(required = false)
    private JWTSecurityConfigurationExtender configurationExtender;

    @Autowired
    private JWTUserAccessService jwtUserAccessService;

    protected String getPublicKey() {
        return publicKey;
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) {
        if (samlAuthenticationProvider != null) {
            auth.authenticationProvider(samlAuthenticationProvider);
        }
        auth.authenticationProvider(jwtAuthenticationProvider());
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        if (samlEntryPoint != null && isNotBlankStringArray(redirectedUrls)) {
            http.exceptionHandling()
                    .defaultAuthenticationEntryPointFor(samlEntryPoint, getRequestMatcher(redirectedUrls))
                .and()
                    .requestCache().requestCache(requestCache());
        }

        final RequestMatcher securityRequestMatcher = getRequestMatcher(securedUrls);
        http.csrf().disable()
            .exceptionHandling()
                .defaultAuthenticationEntryPointFor(new RestAuthenticationEntryPoint(), securityRequestMatcher)
            .and()
            .sessionManagement().sessionCreationPolicy(
                    disableJwtSession ? SessionCreationPolicy.NEVER : SessionCreationPolicy.IF_REQUIRED)
            .and()
            .requestMatcher(securityRequestMatcher)
            .authorizeRequests()
                .antMatchers(HttpMethod.OPTIONS).permitAll();

        final String[] publicResources = getPublicResources();
        if (isNotBlankStringArray(publicResources)) {
            http.authorizeRequests().antMatchers(publicResources).permitAll();
        }
        http.authorizeRequests()
                .antMatchers(securedUrls).hasAnyAuthority(authoritiesWithSecuredAccess);

        if (configurationExtender != null) {
            configurationExtender.configure(http);
        }

        http.addFilterBefore(getJwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    private String[] getPublicResources() {
        final List<String> resources = new ArrayList<>(Arrays.asList(publicUrls));
        resources.add(errorControllerPath);
        return resources.stream()
                .filter(StringUtils::isNotBlank)
                .toArray(String[]::new);
    }

    @Bean
    public JWTTokenVerifier jwtTokenVerifier() {
        return new JWTTokenVerifier(getPublicKey());
    }

    @Bean
    protected JWTAuthenticationProvider jwtAuthenticationProvider() {
        return new JWTAuthenticationProvider(jwtTokenVerifier(), jwtUserAccessService);
    }

    protected JWTAuthenticationFilter getJwtAuthenticationFilter() {
        return new JWTAuthenticationFilter(jwtTokenVerifier(), jwtUserAccessService);
    }

    private RequestCache requestCache() {
        final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setRequestMatcher(getRequestMatcher(redirectedUrls));
        return requestCache;
    }
}
