/*
 * Copyright 2022 EPAM Systems, Inc. (https://www.epam.com/)
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

package com.epam.pipeline.manager.cloudaccess;

import com.epam.pipeline.entity.cloudaccess.CloudAccessManagementConfig;
import com.epam.pipeline.entity.cloudaccess.CloudUserAccessKeys;
import com.epam.pipeline.entity.cloudaccess.policy.CloudAccessPolicy;
import com.epam.pipeline.entity.region.AbstractCloudRegion;
import com.epam.pipeline.entity.region.CloudProvider;
import com.epam.pipeline.entity.user.PipelineUser;
import com.epam.pipeline.manager.cloud.CloudAwareService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CloudAccessManagementFacadeImp implements CloudAccessManagementFacade {

    private Map<CloudProvider, CloudAccessManagementService> cloudAccessServices;

    @Autowired
    public void setCloudAccessServices(final List<CloudAccessManagementService<?>> services) {
        cloudAccessServices = services.stream()
                .collect(Collectors.toMap(CloudAwareService::getProvider, s -> s));
    }

    @Override
    public <R extends AbstractCloudRegion> CloudUserAccessKeys generateAccessKeys(
            final CloudAccessManagementConfig config, final R region, final PipelineUser user) {
        final CloudAccessManagementService<R> accessManagementService = getCloudAccessManagementService(region);

        if (!accessManagementService.doesCloudUserExist(region, getCloudUsername(config, user))) {
            accessManagementService.createCloudUser(region, getCloudUsername(config, user));
        }

        return accessManagementService.generateCloudKeysForUser(region, getCloudUsername(config, user));
    }

    @Override
    public <R extends AbstractCloudRegion> CloudUserAccessKeys getAccessKeys(final CloudAccessManagementConfig config,
                                                                             final R region,
                                                                             final PipelineUser user,
                                                                             final String keyId) {
        final CloudAccessManagementService<R> accessManagementService = getCloudAccessManagementService(region);

        if (!accessManagementService.doesCloudUserExist(region, getCloudUsername(config, user))) {
            throw new IllegalArgumentException(
                    String.format("There is no cloud user with name: %s!", getCloudUsername(config, user)));
        }
        return accessManagementService.getAccessKeysForUser(region, getCloudUsername(config, user), keyId);
    }

    @Override
    public <R extends AbstractCloudRegion> void revokeKeys(final CloudAccessManagementConfig config,
                                                           final R region,
                                                           final PipelineUser user,
                                                           final String keysId) {
        final CloudAccessManagementService<R> accessManagementService =
                getCloudAccessManagementService(region);

        validateCloudUser(accessManagementService, config, region, user);
        accessManagementService.revokeCloudKeysForUser(region, getCloudUsername(config, user), keysId);
    }

    @Override
    public <R extends AbstractCloudRegion> void deleteUser(final CloudAccessManagementConfig config,
                                                           final R region, final PipelineUser user) {
        getCloudAccessManagementService(region).deleteCloudUser(region, getCloudUsername(config, user));
    }

    @Override
    public <R extends AbstractCloudRegion> CloudAccessPolicy getCloudUserAccessPermissions(
            final CloudAccessManagementConfig config, final R region, final PipelineUser user) {
        final CloudAccessManagementService<R> accessManagementService =
                getCloudAccessManagementService(region);

        validateCloudUser(accessManagementService, config, region, user);

        final String policyName = constructCloudUserPolicyName(config, user);
        return accessManagementService.getCloudUserPermissions(region, getCloudUsername(config, user), policyName);
    }

    @Override
    public <R extends AbstractCloudRegion> CloudAccessPolicy updateCloudUserAccessPolicy(
            final CloudAccessManagementConfig config, final R region, final PipelineUser user,
            final CloudAccessPolicy accessPolicy) {
        final CloudAccessManagementService<R> accessManagementService = getCloudAccessManagementService(region);

        if (!accessManagementService.doesCloudUserExist(region, getCloudUsername(config, user))) {
            accessManagementService.createCloudUser(region, getCloudUsername(config, user));
        }

        final String policyName = constructCloudUserPolicyName(config, user);
        accessManagementService.grantCloudUserPermissions(region, getCloudUsername(config, user),
                policyName, accessPolicy);
        return accessPolicy;
    }

    @Override
    public <R extends AbstractCloudRegion> void revokeCloudUserAccessPermissions(
            final CloudAccessManagementConfig config, final R region, final PipelineUser user) {
        final CloudAccessManagementService<R> accessManagementService =
                getCloudAccessManagementService(region);

        validateCloudUser(accessManagementService, config, region, user);

        final String policyName = constructCloudUserPolicyName(config, user);
        accessManagementService.revokeCloudUserPermissions(region, getCloudUsername(config, user), policyName);
    }

    private String constructCloudUserPolicyName(final CloudAccessManagementConfig config, final PipelineUser user) {
        final String accessPolicyPrefix = config.getCloudAccessPolicyPrefix();
        return String.format("%s%s", accessPolicyPrefix, getCloudUsername(config, user));
    }

    private <R extends AbstractCloudRegion> void validateCloudUser(
            final CloudAccessManagementService<R> accessManagementService,
            final CloudAccessManagementConfig config,
            final R region,
            final PipelineUser user) {
        final String cloudUsername = getCloudUsername(config, user);
        if (!accessManagementService.doesCloudUserExist(region, cloudUsername)) {
            throw new IllegalArgumentException(
                    String.format("There is no cloud user with name: %s!", cloudUsername));
        }
    }

    private String getCloudUsername(final CloudAccessManagementConfig config, final PipelineUser user) {
        return StringUtils.isEmpty(config.getCloudUserNamePrefix())
                ? user.getUserName()
                : String.format("%s%s", config.getCloudUserNamePrefix(), user.getUserName());
    }

    @SuppressWarnings("unchecked")
    private <R extends AbstractCloudRegion> CloudAccessManagementService<R> getCloudAccessManagementService(
            final R region) {
        return Optional.ofNullable(cloudAccessServices.get(region.getProvider()))
                .orElseThrow(() -> new IllegalArgumentException(
                        String.format("Cloud Provider: %s is not supported.", region.getProvider())));
    }
}
