package com.epam.lifescience.security.saml;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLContextProvider;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.stream.Stream;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OptionalSAMLLogoutFilterTest {
    private static final String LOGOUT_PARAMETER = "local";
    private static final String SOME_LOCAL_ENTITY_ID = "someLocalEntityId";
    private static final String SOME_REMOTE_ENTITY_ID = "someRemoteEntityId";

    @Test
    void shouldInvokeChainDoFilterWhenRequiresLogoutIsFalse() throws ServletException, IOException {
        final LogoutHandler[] mockLogoutHandlers = new LogoutHandler[]{Mockito.mock(LogoutHandler.class)};
        final OptionalSAMLLogoutFilter logoutFilterSpy =
                Mockito.spy(new OptionalSAMLLogoutFilter("", mockLogoutHandlers, mockLogoutHandlers));
        doReturn(false).when(logoutFilterSpy).requiresLogout(Mockito.any(), Mockito.any());

        final FilterChain filterChainMock = Mockito.mock(FilterChain.class);
        logoutFilterSpy.processLogout(Mockito.mock(HttpServletRequest.class),
                Mockito.mock(HttpServletResponse.class), filterChainMock);
        verify(filterChainMock, times(1)).doFilter(Mockito.any(), Mockito.any());
    }

    @ParameterizedTest
    @MethodSource("provideCasesForInvokeProcessLogoutThrowTest")
    void shouldThrowWhenInvokeProcessLogout(final SAMLContextProvider samlContextProvider,
                                            final SingleLogoutProfile singleLogoutProfile) {
        final LogoutHandler[] mockLogoutHandlers = new LogoutHandler[]{Mockito.mock(LogoutHandler.class)};
        final OptionalSAMLLogoutFilter logoutFilterSpy =
                Mockito.spy(new OptionalSAMLLogoutFilter("", mockLogoutHandlers, mockLogoutHandlers));
        doReturn(true).when(logoutFilterSpy).requiresLogout(Mockito.any(), Mockito.any());
        doReturn(true).when(logoutFilterSpy).isGlobalLogout(Mockito.any(), Mockito.any());

        final SAMLCredential samlCredentialMock = Mockito.mock(SAMLCredential.class);
        when(samlCredentialMock.getLocalEntityID()).thenReturn(SOME_LOCAL_ENTITY_ID);
        when(samlCredentialMock.getRemoteEntityID()).thenReturn(SOME_REMOTE_ENTITY_ID);

        final Authentication authMock = Mockito.mock(Authentication.class);
        when(authMock.getCredentials()).thenReturn(samlCredentialMock);

        try (MockedStatic<SecurityContextHolder> securityContextHolderMock =
                     Mockito.mockStatic(SecurityContextHolder.class)) {
            final SecurityContext securityContextMock = Mockito.mock(SecurityContext.class);
            when(securityContextMock.getAuthentication()).thenReturn(authMock);
            securityContextHolderMock.when(SecurityContextHolder::getContext).thenReturn(securityContextMock);

            logoutFilterSpy.setContextProvider(samlContextProvider);
            logoutFilterSpy.setProfile(singleLogoutProfile);

            final MockHttpServletRequest requestMock = new MockHttpServletRequest();
            Assertions.assertThrows(ServletException.class,
                () -> logoutFilterSpy.processLogout(requestMock, new MockHttpServletResponse(), new MockFilterChain()));
        }
    }

    static Stream<Arguments> provideCasesForInvokeProcessLogoutThrowTest() throws MetadataProviderException,
            MessageEncodingException, SAMLException {
        final SAMLContextProvider providerMockThrowsMessageEncodingException = Mockito.mock(SAMLContextProvider.class);
        when(providerMockThrowsMessageEncodingException.getLocalAndPeerEntity(Mockito.any(), Mockito.any()))
                .thenThrow(MetadataProviderException.class);

        final SAMLContextProvider samlContextProviderMockDoesntThrow = Mockito.mock(SAMLContextProvider.class);

        final SingleLogoutProfile profileMockThrowsMessageEncodingException = Mockito.mock(SingleLogoutProfile.class);
        doThrow(MessageEncodingException.class).when(profileMockThrowsMessageEncodingException)
                .sendLogoutRequest(Mockito.any(), Mockito.any());

        final SingleLogoutProfile profileMockThrowsSAMLException = Mockito.mock(SingleLogoutProfile.class);
        doThrow(SAMLException.class).when(profileMockThrowsSAMLException)
                .sendLogoutRequest(Mockito.any(), Mockito.any());

        return Stream.of(
                Arguments.of(providerMockThrowsMessageEncodingException, Mockito.mock(SingleLogoutProfile.class)),
                Arguments.of(samlContextProviderMockDoesntThrow, profileMockThrowsMessageEncodingException),
                Arguments.of(samlContextProviderMockDoesntThrow, profileMockThrowsSAMLException)
        );
    }

    @ParameterizedTest
    @MethodSource("provideCasesForInvokingIsGlobalLogout")
    void shouldReturnCorrectValueWhenInvokingIsGlobalLogout(final boolean expectedValue, final String localLogout,
                                                            final Object credentials) {
        final HttpServletRequest requestMock = Mockito.mock(HttpServletRequest.class);
        when(requestMock.getParameter(LOGOUT_PARAMETER)).thenReturn(localLogout);

        final Authentication authMock = Mockito.mock(Authentication.class);
        when(authMock.getCredentials()).thenReturn(credentials);

        final LogoutHandler[] mockLogoutHandlers = new LogoutHandler[]{Mockito.mock(LogoutHandler.class)};
        final OptionalSAMLLogoutFilter logoutFilter = new OptionalSAMLLogoutFilter("",
                mockLogoutHandlers, mockLogoutHandlers);

        Assertions.assertEquals(expectedValue, logoutFilter.isGlobalLogout(requestMock, authMock));
    }

    static Stream<Arguments> provideCasesForInvokingIsGlobalLogout() {
        final SAMLCredential samlCredentialMock = Mockito.mock(SAMLCredential.class);
        return Stream.of(
                Arguments.of(true, null, samlCredentialMock),
                Arguments.of(true, "", samlCredentialMock),
                Arguments.of(true, "false", samlCredentialMock),
                Arguments.of(true, "someValue", samlCredentialMock),
                Arguments.of(false, "true", samlCredentialMock),
                Arguments.of(false, "true", new Object())
        );
    }
}
