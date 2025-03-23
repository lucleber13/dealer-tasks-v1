package com.cbcode.dealertasksV1.Users.security.DTOs.Request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "User login credentials")
public record LoginRequest(
        @Schema(
                description = "User email address",
                example = "user@example.com",
                required = true
        )
        @NotBlank(message = "Email cannot be blank")
        @Email(message = "Email must be a valid email address")
        String email,

        @Schema(
                description = "User's password",
                example = "Password123!",
                required = true
        )
        @NotBlank(message = "Password cannot be blank")
        String password) {
}
