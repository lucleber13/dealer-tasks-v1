package com.cbcode.dealertasksV1.Users.security.DTOs.Request;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public record RefreshTokenRequest(String refreshToken) {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenRequest.class);

    public RefreshTokenRequest {
        logger.info("Refresh token generated");
        validateRefreshToken(refreshToken);
    }

    private void validateRefreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            logger.error("Refresh token cannot be null or empty");
            throw new IllegalArgumentException("Refresh token is null or empty");
        }
    }
}
