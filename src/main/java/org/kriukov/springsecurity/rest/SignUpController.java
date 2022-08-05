package org.kriukov.springsecurity.rest;

import org.kriukov.springsecurity.model.SignUpUserDto;
import org.kriukov.springsecurity.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/")
public class SignUpController {

    @Autowired
    private UserService userService;

    @PostMapping("/user/sign-up")
    public Long signUp(@RequestBody SignUpUserDto signUpUserDto){
        return userService.createUser(signUpUserDto);
    }
}
