package com.epam.lifescience.security.entity;

import com.epam.lifescience.security.entity.jwt.JWTRawToken;
import com.epam.lifescience.security.entity.jwt.JWTTokenClaims;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Data
@NoArgsConstructor
public class UserContext implements UserDetails {
    private JWTRawToken jwtRawToken;
    private Long userId;
    private String userName;
    private String orgUnitId;
    private List<String> roles = new ArrayList<>();
    private List<String> groups = new ArrayList<>();
    /**
     * Defines if user is logged in through an external service
     */
    private boolean external;

    public UserContext(final JWTRawToken jwtRawToken, final JWTTokenClaims claims) {
        this.jwtRawToken = jwtRawToken;
        this.userId = Optional.ofNullable(claims.getUserId()).filter(NumberUtils::isDigits).map(Long::parseLong)
                .orElse(null);
        this.userName = claims.getUserName().toUpperCase();
        this.orgUnitId = claims.getOrgUnitId();
        this.roles = claims.getRoles();
        this.groups = claims.getGroups();
        this.external = claims.isExternal();
    }

    public UserContext(final Long id, final String userName) {
        this.userId = id;
        this.userName = userName;
        this.orgUnitId = "";
    }

    public UserContext(final SecurityConfigUser user) {
        this.userName = user.getUserName();
        this.userId = user.getId();
        this.roles = user.getRoles();
        this.groups = user.getGroups();
    }

    public JWTTokenClaims toClaims() {
        return JWTTokenClaims.builder()
                .userId(Optional.ofNullable(userId).map(Objects::toString).orElse(null))
                .userName(userName)
                .orgUnitId(orgUnitId)
                .roles(roles)
                .groups(groups)
                .external(external)
                .build();
    }

    @Override
    public List<GrantedAuthority> getAuthorities() {
        return Stream.concat(
                        ListUtils.emptyIfNull(roles).stream(),
                        ListUtils.emptyIfNull(groups).stream())
                .distinct()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return userName;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
