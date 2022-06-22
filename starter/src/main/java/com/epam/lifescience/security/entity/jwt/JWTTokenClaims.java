package com.epam.lifescience.security.entity.jwt;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter @Setter
@Builder
public class JWTTokenClaims {
    public static final String SECURITY_DATE_TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS";

    public static final String CLAIM_USER_ID = "user_id";
    public static final String CLAIM_ORG_UNIT_ID = "org_unit_id";
    public static final String CLAIM_ROLES = "roles";
    public static final String CLAIM_GROUPS = "groups";
    public static final String CLAIM_EXTERNAL = "external";

    @JsonProperty("jti")
    private String jwtTokenId;
    @JsonProperty("user_id")
    private String userId;
    @JsonProperty("username")
    private String userName;
    @JsonProperty("org_unit_id")
    private String orgUnitId;
    @JsonProperty("issued_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = SECURITY_DATE_TIME_FORMAT)
    private LocalDateTime issuedAt;
    @JsonProperty("expires_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = SECURITY_DATE_TIME_FORMAT)
    private LocalDateTime expiresAt;
    private List<String> roles;
    private List<String> groups;
    private boolean external;
}
