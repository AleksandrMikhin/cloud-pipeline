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

import com.epam.pipeline.entity.cloudaccess.key.CloudUserAccessKeys;
import com.epam.pipeline.entity.cloudaccess.policy.CloudAccessPolicy;
import com.epam.pipeline.entity.region.AbstractCloudRegion;
import com.epam.pipeline.manager.cloud.CloudAwareService;

public interface CloudAccessManagementService<T extends AbstractCloudRegion> extends CloudAwareService {

    boolean doesCloudUserExist(T region, String username);

    void createCloudUser(T region, String username);

    void deleteCloudUser(T region, String username);

    void grantCloudUserPermissions(T region, String username, String policyName, CloudAccessPolicy userPolicy);

    void revokeCloudUserPermissions(T region, String username, String policyName);

    CloudUserAccessKeys generateCloudKeysForUser(T region, String username);

    CloudUserAccessKeys getAccessKeysForUser(T region, String username, String keyId);

    void revokeCloudKeysForUser(T region, String username, String keyId);

    CloudAccessPolicy getCloudUserPermissions(T region, String username, String format);
}
