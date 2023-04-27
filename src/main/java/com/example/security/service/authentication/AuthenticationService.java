package com.example.security.service.authentication;

import com.example.security.dto.auth.AuthenticationRequest;
import com.example.security.dto.auth.AuthenticationResponse;
import com.example.security.dto.auth.RegisterRequest;

public interface AuthenticationService {
    AuthenticationResponse register(RegisterRequest request);

    AuthenticationResponse authenticate(AuthenticationRequest request);
}
