package com.cbcode.dealertasksV1.Users.controller;

import com.cbcode.dealertasksV1.Users.security.AuthService;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.LoginRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.PasswordResetDto;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.RefreshTokenRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.ResetPasswordRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Response.JwtAuthResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

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

    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthResponse> refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        return ResponseEntity.ok(authService.refreshToken(refreshTokenRequest));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<PasswordResetDto> forgotPassword(@RequestBody Map<String, String> request) {
        return ResponseEntity.ok(authService.forgotPassword(request.get("email")));
    }

    @PostMapping("/validate-reset-token")
    public ResponseEntity<PasswordResetDto> validateResetToken(@RequestParam String token) {
        return ResponseEntity.ok(authService.validateResetToken(token));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest) {
        authService.resetPassword(resetPasswordRequest.token(), resetPasswordRequest.password());
        return ResponseEntity.ok().build();
    }
}

