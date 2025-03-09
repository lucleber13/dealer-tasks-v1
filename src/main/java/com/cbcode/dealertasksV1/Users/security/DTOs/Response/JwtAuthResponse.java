package com.cbcode.dealertasksV1.Users.security.DTOs.Response;

public record JwtAuthResponse(String accessToken, String refreshToken) {

    public JwtAuthResponse {
        validateAccessToken(accessToken);
        validateRefreshToken(refreshToken);
    }

    private void validateAccessToken(String accessToken) {
        if (accessToken == null || accessToken.isEmpty()) {
            throw new IllegalArgumentException("Access token cannot be null or empty");
        }
    }

    private void validateRefreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new IllegalArgumentException("Refresh token cannot be null or empty");
        }
    }
}
