package com.cbcode.dealertasksV1.Users.security;

import com.cbcode.dealertasksV1.Users.model.DTOs.UserDto;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.LoginRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.RefreshTokenRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Response.JwtAuthResponse;

public interface AuthService {

    JwtAuthResponse login(LoginRequest loginRequest);

    JwtAuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest);

    void logout();

    UserDto forgotPassword(String email);

    UserDto validateResetToken(String token);

    void resetPassword(String token, String newPassword);
}
