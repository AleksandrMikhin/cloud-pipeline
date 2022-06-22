package com.epam.lifescience.security.service;

import com.epam.lifescience.security.entity.UserContext;
import com.epam.lifescience.security.entity.jwt.JWTRawToken;
import com.epam.lifescience.security.entity.jwt.JWTTokenClaims;

public interface JWTUserAccessService {

    UserContext getJwtUser(JWTRawToken jwtRawToken, JWTTokenClaims claims);

}
