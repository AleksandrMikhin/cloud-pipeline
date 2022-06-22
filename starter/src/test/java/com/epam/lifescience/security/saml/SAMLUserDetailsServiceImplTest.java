package com.epam.lifescience.security.saml;

import com.epam.lifescience.security.entity.UserContext;
import com.epam.lifescience.security.service.SAMLUserAccessService;
import com.google.common.collect.ImmutableMap;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml2.core.NameID;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.saml.SAMLCredential;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SAMLUserDetailsServiceImplTest {
    private static final String SOME_USER_NAME = "someUserName";
    private static final String SOME_EMAIL = "some@mail.com";
    private static final String SOME_AUTHORITY = "someAuth";
    private static final String[] GROUP_ATTRIBUTES = new String[]{"GROUP_1", "GROUP_2"};
    private static final String EMAIL = "Email";
    private static final String NAME = "Name";
    private static final String SURNAME = "Surname";
    private static final String EMAIL_SAML_ATTRIBUTE = "emailSamlAttr";
    private static final String NAME_SAML_ATTRIBUTE = "nameSamlAttr";
    private static final List<String> AUTHORITIES = Collections.singletonList(SOME_AUTHORITY);
    private static final Map<String, String> SAML_ATTRIBUTES = ImmutableMap.of(EMAIL, EMAIL_SAML_ATTRIBUTE,
                                                                               NAME, NAME_SAML_ATTRIBUTE,
                                                                               SURNAME, "");

    @Test
    void shouldInvokeParseUserWithCorrectArguments() {
        final Map<String, String> expectedSamlAttributes = ImmutableMap.of(EMAIL, EMAIL_SAML_ATTRIBUTE,
                                                                           NAME, NAME_SAML_ATTRIBUTE);
        final SAMLUserAccessService accessServiceMock = getAccessServiceMock();
        final SAMLUserDetailsServiceImpl userDetailsService = new SAMLUserDetailsServiceImpl(AUTHORITIES,
                SAML_ATTRIBUTES, accessServiceMock, Optional.empty());

        userDetailsService.loadUserBySAML(getSamlCredentialMock());
        verify(accessServiceMock).getSamlUser(eq(SOME_USER_NAME.toUpperCase()),
                eq(Arrays.asList(GROUP_ATTRIBUTES)), eq(expectedSamlAttributes));
    }

    @Test
    void shouldThrowWhenFilterRejectedUser() {
        final List<SAMLUserLoadingFilter> rejectFilters = Collections.singletonList(
            context -> {
                throw new AccessDeniedException("Access denied");
            }
        );

        final SAMLUserAccessService accessServiceMock = getAccessServiceMock();
        final SAMLUserDetailsServiceImpl userDetailsService = new SAMLUserDetailsServiceImpl(AUTHORITIES,
                SAML_ATTRIBUTES, accessServiceMock, Optional.of(rejectFilters));

        Assertions.assertThrows(RuntimeException.class,
            () -> userDetailsService.loadUserBySAML(getSamlCredentialMock()));
    }

    private static SAMLCredential getSamlCredentialMock() {
        final NameID nameIDMock = Mockito.mock(NameID.class);
        when(nameIDMock.getValue()).thenReturn(SOME_USER_NAME);

        final SAMLCredential samlCredentialMock = Mockito.mock(SAMLCredential.class);
        when(samlCredentialMock.getNameID()).thenReturn(nameIDMock);
        when(samlCredentialMock.getAttributeAsStringArray(SOME_AUTHORITY)).thenReturn(GROUP_ATTRIBUTES.clone());
        when(samlCredentialMock.getAttributeAsString(EMAIL_SAML_ATTRIBUTE)).thenReturn(SOME_EMAIL);
        when(samlCredentialMock.getAttributeAsString(NAME_SAML_ATTRIBUTE)).thenReturn(SOME_USER_NAME);
        when(samlCredentialMock.getAttributeAsString(SURNAME)).thenReturn(null);

        return samlCredentialMock;
    }

    private static SAMLUserAccessService getAccessServiceMock() {
        final SAMLUserAccessService accessServiceMock = Mockito.mock(SAMLUserAccessService.class);
        when(accessServiceMock.getSamlUser(any(), any(), any())).thenReturn(new UserContext(1L, SOME_USER_NAME));

        return accessServiceMock;
    }
}
