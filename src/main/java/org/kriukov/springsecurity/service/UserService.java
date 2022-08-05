package org.kriukov.springsecurity.service;

import org.kriukov.springsecurity.model.SignUpUserDto;
import org.kriukov.springsecurity.model.UserDto;

public interface UserService {

    UserDto getByUsername(String username);

    Long createUser(SignUpUserDto signUpUserDto);
}
