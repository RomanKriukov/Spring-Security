package org.kriukov.springsecurity.service;

import org.kriukov.springsecurity.model.Role;
import org.kriukov.springsecurity.model.SignUpUserDto;
import org.kriukov.springsecurity.model.User;
import org.kriukov.springsecurity.model.UserDto;
import org.kriukov.springsecurity.repository.UserRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService{

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ModelMapper modelMapper;

    @Override
    public UserDto getByUsername(String username) {

        return modelMapper.map(userRepository.findByUsername(username), UserDto.class);
    }

    @Override
    public Long createUser(SignUpUserDto signUpUserDto) {
        User user = modelMapper.map(signUpUserDto, User.class);
        user.setPassword(bCryptPasswordEncoder.encode(signUpUserDto.getPassword()));
        user.setRole(Role.USER);

        return userRepository.saveAndFlush(user).getId();
    }
}
