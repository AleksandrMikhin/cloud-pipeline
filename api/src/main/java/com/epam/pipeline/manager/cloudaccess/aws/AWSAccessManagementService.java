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

package com.epam.pipeline.manager.cloudaccess.aws;

import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClientBuilder;
import com.amazonaws.services.identitymanagement.model.AccessKey;
import com.amazonaws.services.identitymanagement.model.CreateAccessKeyRequest;
import com.amazonaws.services.identitymanagement.model.CreateAccessKeyResult;
import com.amazonaws.services.identitymanagement.model.CreateUserRequest;
import com.amazonaws.services.identitymanagement.model.CreateUserResult;
import com.amazonaws.services.identitymanagement.model.DeleteAccessKeyRequest;
import com.amazonaws.services.identitymanagement.model.DeleteUserPolicyRequest;
import com.amazonaws.services.identitymanagement.model.DeleteUserRequest;
import com.amazonaws.services.identitymanagement.model.GetUserPolicyRequest;
import com.amazonaws.services.identitymanagement.model.GetUserPolicyResult;
import com.amazonaws.services.identitymanagement.model.GetUserRequest;
import com.amazonaws.services.identitymanagement.model.GetUserResult;
import com.amazonaws.services.identitymanagement.model.NoSuchEntityException;
import com.amazonaws.services.identitymanagement.model.PutUserPolicyRequest;
import com.amazonaws.services.identitymanagement.model.User;
import com.epam.pipeline.entity.cloudaccess.CloudUserAccessKeys;
import com.epam.pipeline.entity.cloudaccess.policy.CloudAccessPolicy;
import com.epam.pipeline.entity.region.AwsRegion;
import com.epam.pipeline.entity.region.CloudProvider;
import com.epam.pipeline.manager.cloud.aws.AWSUtils;
import com.epam.pipeline.manager.cloudaccess.CloudAccessManagementService;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import java.util.Optional;

@Service
public class AWSAccessManagementService implements CloudAccessManagementService<AwsRegion> {

    private static final String AWS_IAM_API_VERSION = "2012-10-17";

    @Override
    public CloudProvider getProvider() {
        return CloudProvider.AWS;
    }

    @Override
    public boolean doesCloudUserExist(AwsRegion region, String username) {
        try {
            return Optional.ofNullable(
                    getIAMClient(region).getUser(new GetUserRequest().withUserName(username))
                    ).map(GetUserResult::getUser).map(User::getUserName).isPresent();
        } catch (NoSuchEntityException e) {
            return false;
        }
    }

    @Override
    public void createCloudUser(AwsRegion region, String username) {
        Optional.ofNullable(getIAMClient(region).createUser(new CreateUserRequest().withUserName(username)))
                .map(CreateUserResult::getUser)
                .orElseThrow(() -> new IllegalStateException(
                        String.format("There is a problem with creation of user with name: %s", username)));
    }

    @Override
    public void deleteCloudUser(final AwsRegion region, final String username) {
        getIAMClient(region).deleteUser(new DeleteUserRequest().withUserName(username));
    }

    @Override
    public void grantCloudUserPermissions(final AwsRegion region, final String policyName,
                                          final String username,
                                          final CloudAccessPolicy userPolicy) {
        final PutUserPolicyRequest putUserPolicyRequest = new PutUserPolicyRequest()
                .withUserName(username)
                .withPolicyName(userPolicy.getName())
                .withPolicyDocument(AWSPolicyMapper.toPolicyDocument(userPolicy, AWS_IAM_API_VERSION));
        getIAMClient(region).putUserPolicy(putUserPolicyRequest);
    }

    @Override
    public void revokeCloudUserPermissions(final AwsRegion region, final String username, final String policyName) {
        final DeleteUserPolicyRequest putUserPolicyRequest = new DeleteUserPolicyRequest()
                .withUserName(username)
                .withPolicyName(policyName);
        getIAMClient(region).deleteUserPolicy(putUserPolicyRequest);
    }

    @Override
    public CloudUserAccessKeys generateCloudKeysForUser(final AwsRegion region, final String username) {
        final CreateAccessKeyResult accessKey = getIAMClient(region)
                .createAccessKey(new CreateAccessKeyRequest().withUserName(username));
        return CloudUserAccessKeys.builder().cloudProvider(getProvider())
                .id(accessKey.getAccessKey().getAccessKeyId())
                .credentialsFile(generateAwsCredentialsFile(accessKey.getAccessKey()))
                .configFile(generateAwsConfigFile(region))
                .build();
    }

    @Override
    public void revokeCloudKeysForUser(final AwsRegion region, final String username, final String keyId) {
        getIAMClient(region).deleteAccessKey(
                new DeleteAccessKeyRequest().withUserName(username).withAccessKeyId(keyId)
        );
    }

    @Override
    public CloudAccessPolicy getCloudUserPermissions(final AwsRegion region, final String username,
                                                     final String policyName) {
        final GetUserPolicyResult userPolicy = getIAMClient(region).getUserPolicy(
                new GetUserPolicyRequest().withUserName(username).withPolicyName(policyName)
        );
        Assert.hasText(userPolicy.getUserName(), "Empty cloud user name!");
        Assert.hasText(userPolicy.getPolicyDocument(), "Empty policy document!");
        return AWSPolicyMapper.toCloudUserAccessPolicy(userPolicy.getPolicyName(), userPolicy.getPolicyDocument());
    }

    public AmazonIdentityManagement getIAMClient(final AwsRegion awsRegion) {
        return AmazonIdentityManagementClientBuilder
                .standard()
                .withCredentials(AWSUtils.getCredentialsProvider(awsRegion))
                .build();
    }

    private String generateAwsCredentialsFile(final AccessKey accessKey) {
        return String.format("[default]\n" +
                "aws_access_key_id = %s\n" +
                "aws_secret_access_key = %s", accessKey.getAccessKeyId(), accessKey.getSecretAccessKey());
    }

    private String generateAwsConfigFile(final AwsRegion region) {
        return String.format("[default]\n" +
                "aws_access_key_id = %s", region.getRegionCode());
    }
}
