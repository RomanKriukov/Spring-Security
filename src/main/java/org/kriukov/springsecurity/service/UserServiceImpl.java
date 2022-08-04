package org.kriukov.springsecurity.service;

import org.kriukov.springsecurity.model.User;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService{

    @Override
    public User getByUsername(String username) {
        return new User();
    }
}
