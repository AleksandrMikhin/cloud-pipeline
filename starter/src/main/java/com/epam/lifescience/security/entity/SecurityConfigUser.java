package com.epam.lifescience.security.entity;

import java.util.List;

public interface SecurityConfigUser {

    String getUserName();

    Long getId();

    List<String> getRoles();

    List<String> getGroups();

}
