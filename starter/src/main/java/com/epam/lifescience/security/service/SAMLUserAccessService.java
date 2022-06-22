package com.epam.lifescience.security.service;

import com.epam.lifescience.security.entity.UserContext;

import java.util.List;
import java.util.Map;

public interface SAMLUserAccessService {

    UserContext getSamlUser(String userName, List<String> groups, Map<String, String> attributes);

}
