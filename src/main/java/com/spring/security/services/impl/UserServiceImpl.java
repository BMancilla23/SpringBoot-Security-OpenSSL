package com.spring.security.services.impl;

import java.util.List;

import org.springframework.stereotype.Service;

import com.spring.security.persistence.entities.UserEntity;
import com.spring.security.persistence.repositories.UserRepository;
import com.spring.security.services.IUserService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements IUserService{
    
    private final UserRepository userRepository;

    @Override
    public List<UserEntity> findAllUsers() {
       return userRepository.findAll();
    }


}
