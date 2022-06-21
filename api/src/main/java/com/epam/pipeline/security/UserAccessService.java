/*
 * Copyright 2017-2021 EPAM Systems, Inc. (https://www.epam.com/)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.epam.pipeline.security;

import com.epam.lifescience.security.entity.jwt.JWTRawToken;
import com.epam.lifescience.security.entity.jwt.JWTTokenClaims;
import com.epam.lifescience.security.entity.UserContext;
import com.epam.lifescience.security.exception.jwt.TokenVerificationException;
import com.epam.lifescience.security.service.JWTUserAccessService;
import com.epam.lifescience.security.service.SAMLUserAccessService;
import com.epam.pipeline.common.MessageConstants;
import com.epam.pipeline.common.MessageHelper;
import com.epam.pipeline.dto.quota.QuotaActionType;
import com.epam.pipeline.entity.user.DefaultRoles;
import com.epam.pipeline.entity.user.GroupStatus;
import com.epam.pipeline.entity.user.PipelineUser;
import com.epam.pipeline.entity.user.Role;
import com.epam.pipeline.entity.utils.DateUtils;
import com.epam.pipeline.manager.preference.PreferenceManager;
import com.epam.pipeline.manager.preference.SystemPreferences;
import com.epam.pipeline.manager.quota.QuotaService;
import com.epam.pipeline.manager.security.GrantPermissionManager;
import com.epam.pipeline.manager.user.RoleManager;
import com.epam.pipeline.manager.user.UserManager;
import com.epam.pipeline.security.saml.SamlUserRegisterStrategy;
import com.epam.pipeline.utils.PipelineUserUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Service
public class UserAccessService implements JWTUserAccessService, SAMLUserAccessService {

    @Autowired
    private UserManager userManager;
    @Autowired
    private RoleManager roleManager;
    @Autowired
    private MessageHelper messageHelper;
    @Autowired
    private GrantPermissionManager permissionManager;
    @Value("${jwt.validate.token.user:false}")
    private boolean validateUser;
    @Value("${saml.user.auto.create:EXPLICIT}")
    private SamlUserRegisterStrategy autoCreateUsers;
    @Value("${saml.user.allow.anonymous:false}")
    private boolean allowAnonymous;
    @Value("${saml.user.blocked.attribute:}")
    private String blockedAttribute;
    @Value("${saml.user.blocked.attribute.true.val:true}")
    private String blockedAttributeTrueValue;

    @Autowired
    private PreferenceManager preferenceManager;
    @Autowired
    private QuotaService quotaService;

    @Override
    public UserContext getSamlUser(final String userName, final List<String> groups,
                                   final Map<String, String> attributes) {

        final UserContext userContext = Optional.ofNullable(userManager.loadUserByName(userName))
                .map(loadedUser -> processRegisteredUser(userName, groups, attributes, loadedUser))
                .orElseGet(() -> processNewUser(userName, groups, attributes));

        validateUserContextGroupsBlockStatus(userContext);

        if (hasBlockedStatusAttribute(attributes)) {
            Optional.ofNullable(userContext.getUserId())
                    .ifPresent(id -> userManager.updateUserBlockingStatus(id, true));
            throwUserIsBlocked(userName);
        }
        return userContext;
    }

    private boolean hasBlockedStatusAttribute(final Map<String, String> attributes) {
        return StringUtils.isNotBlank(blockedAttribute) &&
                blockedAttributeTrueValue.equalsIgnoreCase(attributes.get(blockedAttribute));
    }

    @Override
    public UserContext getJwtUser(final JWTRawToken jwtRawToken, final JWTTokenClaims claims) {
        final UserContext jwtUser = new UserContext(jwtRawToken, claims);
        if (!validateUser) {
            return jwtUser;
        }
        final PipelineUser pipelineUser = userManager.loadUserByName(jwtUser.getUsername());
        if (pipelineUser == null) {
            log.info("Failed to find user by name {}. Access is still allowed.", jwtUser.getUsername());
            return jwtUser;
        }
        if (needToUpdateUserLastLogin(pipelineUser)) {
            userManager.updateLastLoginDate(pipelineUser);
        }
        if (!jwtUser.getUserId().equals(pipelineUser.getId())) {
            throw new TokenVerificationException(String.format(
                    "Invalid JWT token provided for user %s: id %d doesn't match expected value %d.",
                    jwtUser.getUsername(), jwtUser.getUserId(), pipelineUser.getId()));
        }
        validateUserBlockStatus(pipelineUser);
        validateUserGroupsBlockStatus(pipelineUser);
        jwtUser.setRoles(PipelineUserUtils.getRoleNames(pipelineUser));
        jwtUser.setGroups(pipelineUser.getGroups());
        return jwtUser;
    }

    public void validateUserBlockStatus(final PipelineUser user) {
        if (user.isBlocked()) {
            log.info("Authentication failed! User {} is blocked!", user.getUserName());
            throwUserIsBlocked(user.getUserName());
        }
        if (user.isAdmin()) {
            return;
        }
        quotaService.findActiveActionForUser(user, QuotaActionType.BLOCK)
                .ifPresent(quota -> {
                    log.info("Logging of user is blocked due to quota applied {}", quota);
                    throwUserIsBlocked(user.getUserName());
                });
    }

    public void validateUserContextGroupsBlockStatus(final UserContext userContext) {
        final List<String> groups = userContext.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        validateGroupsBlockStatus(userContext.getUsername(), groups);
    }

    public void validateUserGroupsBlockStatus(final PipelineUser user) {
        final List<String> groups = PipelineUserUtils.getAuthorities(user);
        validateGroupsBlockStatus(user.getUserName(), groups);
    }

    private void validateGroupsBlockStatus(final String userName, final List<String > groups) {
        final boolean blocked = ListUtils.emptyIfNull(userManager.loadGroupBlockingStatus(groups))
                .stream()
                .anyMatch(GroupStatus::isBlocked);
        if (blocked) {
            log.info("Authentication failed! User {} is blocked due to one of his groups is blocked!", userName);
            throwUserIsBlocked(userName);
        }
    }

    public void throwUserIsBlocked(final String userName) {
        throw new LockedException("User: " + userName + " is blocked!");
    }

    private UserContext processRegisteredUser(final String userName, final List<String> groups,
                                              final Map<String, String> attributes, final PipelineUser loadedUser) {
        log.debug("Found user by name {}", userName);
        loadedUser.setUserName(userName);
        validateUserBlockStatus(loadedUser);
        final List<Long> roles = loadedUser.getRoles().stream().map(Role::getId).collect(Collectors.toList());
        if (loadedUser.getFirstLoginDate() == null) {
            userManager.updateUserFirstLoginDate(loadedUser.getId(), DateUtils.nowUTC());
        }
        userManager.updateLastLoginDate(loadedUser);
        if (userManager.needToUpdateUser(groups, attributes, loadedUser)) {
            final PipelineUser updatedUser =
                    userManager.updateUserSAMLInfo(loadedUser.getId(), userName, roles, groups, attributes);
            log.debug("Updated user groups {} ", groups);
            return PipelineUserUtils.toUserContext(updatedUser);
        } else {
            return PipelineUserUtils.toUserContext(loadedUser);
        }
    }

    private UserContext processNewUser(final String userName, final List<String> groups,
                                       final Map<String, String> attributes) {
        log.debug(messageHelper.getMessage(MessageConstants.ERROR_USER_NAME_NOT_FOUND, userName));
        switch (autoCreateUsers) {
            case EXPLICIT:
                return allowAnonymous ? createAnonymousUser(userName, groups) :
                        throwUserNotExplicitlyRegistered(userName);
            case EXPLICIT_GROUP:
                if (permissionManager.isGroupRegistered(groups)) {
                    return createUser(userName, groups, attributes);
                } else {
                    return allowAnonymous ? createAnonymousUser(userName, groups) :
                            throwGroupNotExplicitlyRegistered(userName, groups);
                }
            default:
                return createUser(userName, groups, attributes);
        }
    }

    private UserContext throwUserNotExplicitlyRegistered(final String userName) {
        log.error(messageHelper.getMessage(MessageConstants.ERROR_USER_NOT_REGISTERED_EXPLICITLY, userName));
        throw new UsernameNotFoundException(
                messageHelper.getMessage(MessageConstants.ERROR_USER_NOT_REGISTERED_EXPLICITLY, userName));
    }

    private UserContext throwGroupNotExplicitlyRegistered(final String userName, final List<String> groups) {
        log.error(messageHelper.getMessage(MessageConstants.ERROR_USER_NOT_REGISTERED_GROUP_EXPLICITLY, userName));
        throw new UsernameNotFoundException(
                messageHelper.getMessage(MessageConstants.ERROR_USER_NOT_REGISTERED_GROUP_EXPLICITLY,
                        String.join(", ", groups), userName));
    }

    private UserContext createUser(final String userName, final List<String> groups,
                                   final Map<String, String> attributes) {
        final List<Long> roles = roleManager.getDefaultRolesIds();
        final PipelineUser createdUser = userManager.createUser(userName,
                roles, groups, attributes, null);
        userManager.updateUserFirstLoginDate(createdUser.getId(), DateUtils.nowUTC());
        log.debug("Created user {} with groups {}", userName, groups);
        final UserContext userContext = new UserContext(createdUser.getId(), userName);
        userContext.setRoles(PipelineUserUtils.getRoleNames(createdUser));
        userContext.setGroups(createdUser.getGroups());
        return userContext;
    }

    private UserContext createAnonymousUser(final String userName, final List<String> groups) {
        log.debug("Created anonymous user {} with groups {}", userName, groups);
        final UserContext userContext = new UserContext(null, userName);
        userContext.setGroups(groups);
        userContext.setRoles(Collections.singletonList(DefaultRoles.ROLE_ANONYMOUS_USER.getName()));
        return userContext;
    }

    private boolean needToUpdateUserLastLogin(final PipelineUser user) {
        if (Objects.isNull(user.getLastLoginDate())) {
            return true;
        }

        final Integer threshold = preferenceManager.getPreference(
                SystemPreferences.SYSTEM_USER_JWT_LAST_LOGIN_THRESHOLD);
        return DateUtils.hoursBetweenDates(user.getLastLoginDate(), DateUtils.nowUTC()) >= threshold;
    }
}
