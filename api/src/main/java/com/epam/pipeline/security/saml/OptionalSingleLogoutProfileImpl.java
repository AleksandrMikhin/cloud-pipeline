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

package com.epam.pipeline.security.saml;

import org.opensaml.common.SAMLException;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;

public class OptionalSingleLogoutProfileImpl extends SingleLogoutProfileImpl {

    @Override
    public void sendLogoutRequest(SAMLMessageContext context, SAMLCredential credential)
            throws SAMLException, MetadataProviderException, MessageEncodingException {
        try {
            super.sendLogoutRequest(context, credential);
        } catch (MetadataProviderException e) {
            log.debug(e.getMessage(), e);
        }
    }

    @Override
    public void sendLogoutResponse(SAMLMessageContext context, String statusCode,
            String statusMessage)
            throws MetadataProviderException, SAMLException, MessageEncodingException {
        try {
            super.sendLogoutResponse(context, statusCode, statusMessage);
        } catch (MetadataProviderException e) {
            log.debug(e.getMessage(), e);
        }
    }
}
