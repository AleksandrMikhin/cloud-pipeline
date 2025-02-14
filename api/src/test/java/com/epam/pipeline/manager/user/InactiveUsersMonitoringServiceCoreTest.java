/*
 * Copyright 2021 EPAM Systems, Inc. (https://www.epam.com/)
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

package com.epam.pipeline.manager.user;

import com.epam.pipeline.entity.user.DefaultRoles;
import com.epam.pipeline.entity.user.GroupStatus;
import com.epam.pipeline.entity.user.PipelineUser;
import com.epam.pipeline.manager.ldap.LdapBlockedUsersManager;
import com.epam.pipeline.manager.notification.NotificationManager;
import com.epam.pipeline.manager.preference.PreferenceManager;
import com.epam.pipeline.manager.preference.SystemPreferences;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.epam.pipeline.test.creator.user.UserCreatorUtils.getPipelineUser;
import static com.epam.pipeline.util.CustomAssertions.notInvoked;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class InactiveUsersMonitoringServiceCoreTest {
    private static final Integer THRESHOLD_DAYS = 3;
    private static final String USER_NAME_1 = "name1";
    private static final String USER_NAME_2 = "name2";
    private static final String USER_NAME_3 = "name3";
    private static final Long ID_1 = 1L;
    private static final Long ID_2 = 2L;
    private static final Long ID_3 = 3L;

    private final UserManager userManager = mock(UserManager.class);
    private final NotificationManager notificationManager = mock(NotificationManager.class);
    private final PreferenceManager preferenceManager = mock(PreferenceManager.class);
    private final LdapBlockedUsersManager ldapManager = mock(LdapBlockedUsersManager.class);
    private final InactiveUsersMonitoringServiceCore monitoringService = new InactiveUsersMonitoringServiceCore(
            userManager, notificationManager, preferenceManager, ldapManager);

    @Before
    public void setup() {
        doReturn(THRESHOLD_DAYS).when(preferenceManager)
                .getPreference(SystemPreferences.SYSTEM_USER_MONITOR_BLOCKED_DAYS);
        doReturn(THRESHOLD_DAYS).when(preferenceManager).getPreference(SystemPreferences.SYSTEM_USER_MONITOR_IDLE_DAYS);
        doReturn(true).when(preferenceManager).getPreference(SystemPreferences.SYSTEM_USER_MONITOR_ENABLED);
    }

    @Test
    public void shouldNotifyBlockedPipelineUsers() {
        doReturn(false).when(preferenceManager).getPreference(
                SystemPreferences.SYSTEM_LDAP_USER_BLOCK_MONITOR_ENABLED);

        final PipelineUser blockedUser = blockedUser(USER_NAME_1, ID_1);
        final PipelineUser activeUser = activeUser(USER_NAME_2, ID_2);

        doReturn(Arrays.asList(blockedUser, activeUser)).when(userManager).loadAllUsers();

        monitoringService.monitor();

        final ArgumentCaptor<List<PipelineUser>> captor = argumentCaptor();
        verify(notificationManager).notifyInactiveUsers(captor.capture(), any());
        final List<PipelineUser> resultUsers = captor.getValue();

        assertThat(resultUsers).hasSize(1);
        assertThat(resultUsers.get(0)).isEqualTo(blockedUser);
    }

    @Test
    public void shouldNotifyBlockedPipelineUsersByGroup() {
        doReturn(false).when(preferenceManager).getPreference(
                SystemPreferences.SYSTEM_LDAP_USER_BLOCK_MONITOR_ENABLED);

        final GroupStatus blockedGroup = blockedGroup();
        final GroupStatus activeGroup = activeGroup();

        final PipelineUser blockedUser = userBlockedByGroup(USER_NAME_1, ID_1);
        final PipelineUser activeUser = activeUser(USER_NAME_2, ID_2);

        doReturn(Arrays.asList(blockedUser, activeUser)).when(userManager).loadAllUsers();
        doReturn(Arrays.asList(blockedGroup, activeGroup)).when(userManager).loadAllGroupsBlockingStatuses();

        monitoringService.monitor();

        final ArgumentCaptor<List<PipelineUser>> captor = argumentCaptor();
        verify(notificationManager).notifyInactiveUsers(captor.capture(), any());
        final List<PipelineUser> resultUsers = captor.getValue();

        assertThat(resultUsers).hasSize(1);
        assertThat(resultUsers.get(0)).isEqualTo(blockedUser);
    }

    @Test
    public void shouldNotifyIdlePipelineUsers() {
        doReturn(false).when(preferenceManager).getPreference(
                SystemPreferences.SYSTEM_LDAP_USER_BLOCK_MONITOR_ENABLED);

        final PipelineUser idleUser = idleUser(USER_NAME_1, ID_1);
        final PipelineUser activeUser = activeUser(USER_NAME_2, ID_2);

        doReturn(Arrays.asList(idleUser, activeUser)).when(userManager).loadAllUsers();

        monitoringService.monitor();

        final ArgumentCaptor<List<PipelineUser>> captor = argumentCaptor();
        verify(notificationManager).notifyInactiveUsers(captor.capture(), any());
        final List<PipelineUser> resultUsers = captor.getValue();

        assertThat(resultUsers).hasSize(1);
        assertThat(resultUsers.get(0)).isEqualTo(idleUser);
    }

    @Test
    public void shouldNotifyPipelineUserThatNeverLogin() {
        doReturn(false).when(preferenceManager).getPreference(
                SystemPreferences.SYSTEM_LDAP_USER_BLOCK_MONITOR_ENABLED);

        final PipelineUser inactiveUser = getPipelineUser(USER_NAME_1, ID_1);
        inactiveUser.setRegistrationDate(LocalDateTime.now().minusDays(THRESHOLD_DAYS + 2));
        final PipelineUser activeUser = activeUser(USER_NAME_2, ID_2);

        doReturn(Arrays.asList(inactiveUser, activeUser)).when(userManager).loadAllUsers();

        monitoringService.monitor();

        final ArgumentCaptor<List<PipelineUser>> captor = argumentCaptor();
        verify(notificationManager).notifyInactiveUsers(captor.capture(), any());
        final List<PipelineUser> resultUsers = captor.getValue();

        assertThat(resultUsers).hasSize(1);
        assertThat(resultUsers.get(0)).isEqualTo(inactiveUser);
    }

    @Test
    public void shouldNotNotifyIfAllPipelineUsersActive() {
        doReturn(false).when(preferenceManager).getPreference(
                SystemPreferences.SYSTEM_LDAP_USER_BLOCK_MONITOR_ENABLED);

        final PipelineUser activeUser1 = activeUser(USER_NAME_2, ID_2);
        final PipelineUser activeUser2 = activeUser(USER_NAME_2, ID_2);

        doReturn(Arrays.asList(activeUser1, activeUser2)).when(userManager).loadAllUsers();

        monitoringService.monitor();

        final ArgumentCaptor<List<PipelineUser>> captor = argumentCaptor();
        verify(notificationManager).notifyInactiveUsers(captor.capture(), any());
        final List<PipelineUser> resultUsers = captor.getValue();

        assertThat(resultUsers).hasSize(0);
    }

    @Test
    public void shouldBlockAndNotifyBlockedLdapUser() {
        doReturn(true).when(preferenceManager).getPreference(
                SystemPreferences.SYSTEM_LDAP_USER_BLOCK_MONITOR_ENABLED);

        final PipelineUser blockedUser = activeUser(USER_NAME_1, ID_1);
        final PipelineUser activeUser1 = activeUser(USER_NAME_2, ID_2);
        final PipelineUser activeUser2 = activeUser(USER_NAME_3, ID_3);
        final List<PipelineUser> allUsers = Arrays.asList(blockedUser, activeUser1, activeUser2);

        doReturn(allUsers).when(userManager).loadAllUsers();
        doReturn(blockedUser).when(userManager).updateUserBlockingStatus(ID_1, true);
        doReturn(Collections.singletonList(blockedUser)).when(ldapManager).filterBlockedUsers(allUsers);

        monitoringService.monitor();

        verify(userManager).updateUserBlockingStatus(ID_1, true);
        verify(ldapManager).filterBlockedUsers(allUsers);
        final ArgumentCaptor<List<PipelineUser>> usersCaptor = argumentCaptor();
        verify(notificationManager).notifyInactiveUsers(any(), usersCaptor.capture());
        final List<PipelineUser> resultUsers = usersCaptor.getValue();

        assertThat(resultUsers).hasSize(1);
        assertThat(resultUsers.get(0)).isEqualTo(blockedUser);
    }

    @Test
    public void shouldNotBlockAndNotifyLdapBlockedAdmin() {
        final PipelineUser blockedAdmin = activeUser(USER_NAME_1, ID_1);
        blockedAdmin.setRoles(Collections.singletonList(DefaultRoles.ROLE_ADMIN.getRole()));

        doReturn(Collections.singletonList(blockedAdmin)).when(userManager).loadAllUsers();

        monitoringService.monitor();

        notInvoked(userManager).updateUserBlockingStatus(ID_1, true);
        notInvoked(ldapManager).filterBlockedUsers(any());
        final ArgumentCaptor<List<PipelineUser>> captor = argumentCaptor();
        verify(notificationManager).notifyInactiveUsers(any(), captor.capture());
        final List<PipelineUser> resultUsers = captor.getValue();

        assertThat(resultUsers).hasSize(0);
    }

    private static PipelineUser activeUser(final String userName, final Long id) {
        final PipelineUser pipelineUser = getPipelineUser(userName, id);
        pipelineUser.setBlocked(false);
        pipelineUser.setLastLoginDate(LocalDateTime.now());
        return pipelineUser;
    }

    private static PipelineUser blockedUser(final String userName, final Long id) {
        final PipelineUser pipelineUser = getPipelineUser(userName, id);
        pipelineUser.setBlocked(true);
        pipelineUser.setBlockDate(LocalDateTime.now().minusDays(THRESHOLD_DAYS + 2));
        return pipelineUser;
    }

    private static PipelineUser idleUser(final String userName, final Long id) {
        final PipelineUser pipelineUser = getPipelineUser(userName, id);
        pipelineUser.setBlocked(false);
        pipelineUser.setLastLoginDate(LocalDateTime.now().minusDays(THRESHOLD_DAYS + 2));
        return pipelineUser;
    }

    private static GroupStatus blockedGroup() {
        return new GroupStatus("BLOCKED", true, LocalDateTime.now().minusDays(THRESHOLD_DAYS + 2));
    }

    private static GroupStatus activeGroup() {
        return new GroupStatus("ACTIVE", false, LocalDateTime.now().minusDays(THRESHOLD_DAYS + 2));
    }

    private static PipelineUser userBlockedByGroup(final String userName, final Long id) {
        final PipelineUser pipelineUser = getPipelineUser(userName, id);
        pipelineUser.setBlocked(false);
        pipelineUser.setGroups(Arrays.asList("BLOCKED", "ACTIVE"));
        return pipelineUser;
    }

    private ArgumentCaptor argumentCaptor() {
        return ArgumentCaptor.forClass((Class) List.class);
    }
}
