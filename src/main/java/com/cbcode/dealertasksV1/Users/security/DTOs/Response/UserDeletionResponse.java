package com.cbcode.dealertasksV1.Users.security.DTOs.Response;

import java.time.LocalDateTime;

public record UserDeletionResponse(
        Long id,
        String email,
        String message,
        LocalDateTime deletedAt
) {
}
