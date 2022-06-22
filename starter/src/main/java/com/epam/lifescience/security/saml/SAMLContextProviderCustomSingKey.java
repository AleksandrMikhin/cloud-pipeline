package com.epam.lifescience.security.saml;

import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.storage.EmptyStorageFactory;
import org.springframework.security.saml.storage.HttpSessionStorageFactory;

import javax.xml.namespace.QName;

public class SAMLContextProviderCustomSingKey extends SAMLContextProviderImpl {

    private final String signingKey;

    public SAMLContextProviderCustomSingKey(final String signingKey,
                                            final boolean validateMessage) {
        this.signingKey = signingKey;
        setStorageFactory(validateMessage ? new HttpSessionStorageFactory() : new EmptyStorageFactory());
    }

    @Override
    protected void populateLocalEntity(final SAMLMessageContext samlContext)
            throws MetadataProviderException {
        final String localEntityId = samlContext.getLocalEntityId();
        final QName localEntityRole = samlContext.getLocalEntityRole();

        if (localEntityId == null) {
            throw new MetadataProviderException("No hosted service provider is configured and no alias was selected");
        }

        final EntityDescriptor entityDescriptor = metadata.getEntityDescriptor(localEntityId);
        final RoleDescriptor roleDescriptor = metadata
                .getRole(localEntityId, localEntityRole, SAMLConstants.SAML20P_NS);
        final ExtendedMetadata extendedMetadata = metadata.getExtendedMetadata(localEntityId);

        if (entityDescriptor == null || roleDescriptor == null) {
            throw new MetadataProviderException("Metadata for entity " + localEntityId +
                    " and role " + localEntityRole + " wasn't found");
        }

        samlContext.setLocalEntityMetadata(entityDescriptor);
        samlContext.setLocalEntityRoleMetadata(roleDescriptor);
        samlContext.setLocalExtendedMetadata(extendedMetadata);

        if (extendedMetadata.getSigningKey() != null) {
            samlContext.setLocalSigningCredential(keyManager.getCredential(extendedMetadata.getSigningKey()));
        } else {
            samlContext.setLocalSigningCredential(keyManager.getCredential(signingKey));
        }
    }
}
