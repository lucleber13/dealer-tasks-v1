package com.cbcode.dealertasksV1.Users.security;

import com.cbcode.dealertasksV1.Users.security.DTOs.Request.LoginRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.PasswordResetDto;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.RefreshTokenRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Response.JwtAuthResponse;

public interface AuthService {

    JwtAuthResponse login(LoginRequest loginRequest);

    JwtAuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest);

    PasswordResetDto forgotPassword(String email);

    PasswordResetDto validateAndInvalidateResetToken(String token);

    void resetPassword(String token, String newPassword);
}
