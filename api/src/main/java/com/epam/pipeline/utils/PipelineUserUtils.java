package com.epam.pipeline.utils;

import com.epam.lifescience.security.entity.UserContext;
import com.epam.pipeline.entity.user.DefaultRoles;
import com.epam.pipeline.entity.user.PipelineUser;
import com.epam.pipeline.entity.user.Role;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.collections4.ListUtils;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SuppressWarnings("HideUtilityClassConstructor")
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class PipelineUserUtils {

    public static PipelineUser toPipelineUser(final UserContext context) {
        return PipelineUser.builder()
                .id(context.getUserId())
                .userName(context.getUsername())
                .roles(toRoles(context.getRoles()))
                .groups(context.getGroups())
                .admin(context.getRoles().stream()
                        .anyMatch(role -> role.equals(DefaultRoles.ROLE_ADMIN.getName())))
                .build();
    }

    public static UserContext toUserContext(final PipelineUser user) {
        final UserContext userContext = new UserContext(user.getId(), user.getUserName());
        userContext.setRoles(getRoleNames(user));
        userContext.setGroups(user.getGroups());
        return userContext;
    }

    public static List<Role> toRoles(final List<String> stringRoles) {
        return ListUtils.emptyIfNull(stringRoles).stream()
                .map(Role::new)
                .collect(Collectors.toList());
    }

    public static List<String> getRoleNames(final PipelineUser user) {
        return ListUtils.emptyIfNull(user.getRoles()).stream()
                .map(Role::getName)
                .collect(Collectors.toList());
    }

    public static List<String> getAuthorities(final PipelineUser user) {
        return Stream.concat(
                        ListUtils.emptyIfNull(user.getRoles()).stream().map(Role::getName),
                        ListUtils.emptyIfNull(user.getGroups()).stream())
                .distinct()
                .collect(Collectors.toList());
    }
}
