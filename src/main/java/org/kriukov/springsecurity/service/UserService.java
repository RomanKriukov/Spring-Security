package org.kriukov.springsecurity.service;

import org.kriukov.springsecurity.model.User;

public interface UserService {

    User getByUsername(String username);
}
