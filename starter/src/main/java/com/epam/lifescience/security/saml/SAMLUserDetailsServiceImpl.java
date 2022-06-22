package com.epam.lifescience.security.saml;

import com.epam.lifescience.security.service.SAMLUserAccessService;
import com.epam.lifescience.security.entity.UserContext;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
public class SAMLUserDetailsServiceImpl implements SAMLUserDetailsService {

    private final List<String> authorities;
    private final Map<String, String> samlAttributes;
    private final SAMLUserAccessService accessService;
    private final List<SAMLUserLoadingFilter> samlUserLoadingFilters;

    public SAMLUserDetailsServiceImpl(@Value("${saml.authorities.attribute.names:}")
                                      final List<String> authorities,
                                      @Value("#{${saml.user.attributes: {:}}}")
                                      final Map<String, String> samlAttributes,
                                      @Autowired
                                      final SAMLUserAccessService accessService,
                                      @Autowired
                                      final Optional<List<SAMLUserLoadingFilter>> samlUserLoadingFilters) {
        this.authorities = authorities;
        this.samlAttributes = samlAttributes;
        this.accessService = accessService;
        this.samlUserLoadingFilters = samlUserLoadingFilters.orElse(Collections.emptyList());
    }

    @Override
    public UserContext loadUserBySAML(final SAMLCredential credential) {
        final String userName = credential.getNameID().getValue().toUpperCase();
        final List<String> groups = readAuthorities(credential);
        final Map<String, String> attributes = readAttributes(credential);
        final UserContext userContext = accessService.getSamlUser(userName, groups, attributes);

        samlUserLoadingFilters.forEach((userFilter) -> userFilter.doFilter(userContext));

        log.info("Successfully authenticate user: " + userContext.getUsername());
        return userContext;
    }

    public List<String> readAuthorities(final SAMLCredential credential) {
        return authorities.stream()
                .filter(StringUtils::isNotBlank)
                .map(authName -> getGroupsFromArrayValue(credential, authName))
                .flatMap(List::stream)
                .collect(Collectors.toList());
    }

    private List<String> getGroupsFromArrayValue(final SAMLCredential credential,
                                                 final String authName) {
        final String[] attributeValues = credential.getAttributeAsStringArray(authName);
        if (ArrayUtils.isEmpty(attributeValues)) {
            return Collections.emptyList();
        }

        return Arrays.stream(attributeValues)
                .filter(StringUtils::isNotBlank)
                .map(String::toUpperCase)
                .collect(Collectors.toList());
    }

    public Map<String, String> readAttributes(final SAMLCredential credential) {
        return samlAttributes.entrySet().stream()
                .filter(attribute -> credential.getAttributeAsString(attribute.getValue()) != null)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
