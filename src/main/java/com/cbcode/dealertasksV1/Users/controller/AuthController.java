package com.cbcode.dealertasksV1.Users.controller;

import com.cbcode.dealertasksV1.Users.security.AuthService;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.LoginRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Response.JwtAuthResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping( "/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }


    @PostMapping("/login")
    public ResponseEntity<JwtAuthResponse> login(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.login(loginRequest));
    }
}

