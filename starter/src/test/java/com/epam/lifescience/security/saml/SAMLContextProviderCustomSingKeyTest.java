package com.epam.lifescience.security.saml;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataManager;

import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SAMLContextProviderCustomSingKeyTest {
    private static final String SOME_SINGING_KEY = "someKey";
    private static final String SOME_LOCAL_ENTITY_ID = "someId";

    @ParameterizedTest()
    @MethodSource("provideNegativeCasesForPopulateLocalEntity")
    void shouldThrowWhenInvokePopulateLocalEntity(final MetadataManager metadataManagerMock,
                                                  final String localEntityId) {
        final SAMLContextProviderCustomSingKey contextProvider =
                new SAMLContextProviderCustomSingKey(SOME_SINGING_KEY, true);

        contextProvider.setMetadata(metadataManagerMock);

        final SAMLMessageContext samlContextMock = Mockito.mock(SAMLMessageContext.class);
        when(samlContextMock.getLocalEntityId()).thenReturn(localEntityId);

        Assertions.assertThrows(MetadataProviderException.class,
            () -> contextProvider.populateLocalEntity(samlContextMock));
    }

    static Stream<Arguments> provideNegativeCasesForPopulateLocalEntity() throws MetadataProviderException {
        final EntityDescriptor entityDescriptorMock = Mockito.mock(EntityDescriptor.class);
        final RoleDescriptor roleDescriptorMock = Mockito.mock(RoleDescriptor.class);

        return Stream.of(
                Arguments.of(getMetadataManagerMock(null, roleDescriptorMock), SOME_LOCAL_ENTITY_ID),
                Arguments.of(getMetadataManagerMock(entityDescriptorMock, null), SOME_LOCAL_ENTITY_ID),
                Arguments.of(getMetadataManagerMock(entityDescriptorMock, roleDescriptorMock), null)
        );
    }

    @Test
    void shouldMakeSettingsSamlContext() throws MetadataProviderException {
        final SAMLContextProviderCustomSingKey contextProvider =
                new SAMLContextProviderCustomSingKey(SOME_SINGING_KEY, true);

        contextProvider.setKeyManager(Mockito.mock(KeyManager.class));
        contextProvider.setMetadata(getMetadataManagerMock(Mockito.mock(EntityDescriptor.class),
                Mockito.mock(RoleDescriptor.class)));

        final SAMLMessageContext samlContextMock = Mockito.mock(SAMLMessageContext.class);
        when(samlContextMock.getLocalEntityId()).thenReturn(SOME_LOCAL_ENTITY_ID);

        Assertions.assertDoesNotThrow(() -> contextProvider.populateLocalEntity(samlContextMock));
        verify(samlContextMock).setLocalEntityMetadata(any());
        verify(samlContextMock).setLocalEntityRoleMetadata(any());
        verify(samlContextMock).setLocalExtendedMetadata(any());
        verify(samlContextMock).setLocalSigningCredential(any());
    }

    static MetadataManager getMetadataManagerMock(final EntityDescriptor entityDescriptor,
                                                final RoleDescriptor roleDescriptor) throws MetadataProviderException {
        final MetadataManager metadataManagerMock = Mockito.mock(MetadataManager.class);
        when(metadataManagerMock.getEntityDescriptor(anyString())).thenReturn(entityDescriptor);
        when(metadataManagerMock.getRole(any(), any(), any())).thenReturn(roleDescriptor);
        when(metadataManagerMock.getExtendedMetadata(any())).thenReturn(Mockito.mock(ExtendedMetadata.class));
        return metadataManagerMock;
    }
}
