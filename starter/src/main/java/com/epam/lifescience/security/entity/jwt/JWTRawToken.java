package com.epam.lifescience.security.entity.jwt;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.io.Serializable;

import static com.epam.lifescience.security.utils.AuthorizationUtils.BEARER_PREFIX;

@Getter
@AllArgsConstructor
@EqualsAndHashCode
public class JWTRawToken implements Serializable {
    private final String token;

    public String toHeader() {
        return BEARER_PREFIX + token;
    }

}
