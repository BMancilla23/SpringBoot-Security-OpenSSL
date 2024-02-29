package com.spring.security.services;

import java.util.HashMap;

import com.spring.security.persistence.entities.UserEntity;
import com.spring.security.services.models.dtos.LoginDTO;
import com.spring.security.services.models.dtos.ResponseDTO;

public interface IAuthService {
    public HashMap<String, String> login(LoginDTO login) throws Exception;

    public ResponseDTO register(UserEntity user) throws Exception;
}
