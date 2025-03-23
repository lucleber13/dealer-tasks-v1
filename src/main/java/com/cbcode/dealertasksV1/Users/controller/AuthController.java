package com.cbcode.dealertasksV1.Users.controller;

import com.cbcode.dealertasksV1.Users.security.AuthService;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.LoginRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.PasswordResetDto;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.RefreshTokenRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.ResetPasswordRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Response.JwtAuthResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@CrossOrigin("*")
@Validated
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }


    @Operation(
            summary = "User login endpoint",
            description = "Authenticates a registered user using their email and password. Returns a JWT access token and refresh token on success."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "User logged in successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = JwtAuthResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid request format (e.g., missing or malformed email/password)",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Invalid request: Email cannot be null\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid email or password",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Invalid email or password\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "429",
                    description = "Too many login attempts due to rate limiting",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Too many login attempts, please try again later\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Server error occurred\"}")
                    )
            )
    })
    @PostMapping("/login")
    public ResponseEntity<JwtAuthResponse> login(
            @Parameter(
                    description = "User login credentials (email and password)",
                    required = true,
                    content = @Content(
                            schema = @Schema(implementation = LoginRequest.class),
                            examples = @ExampleObject(value = "{\"email\": \"user@example.com\", \"password\": \"Password123!\"}")
                    )
            )
            @Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.login(loginRequest));
    }

    @Operation(
            summary = "Refresh JWT token",
            description = "Generates a new access token using a valid refresh token."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Token refreshed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = JwtAuthResponse.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid or missing refresh token",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Refresh token is required\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid or expired refresh token",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Invalid or expired refresh token\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Server error occurred\"}")
                    )
            )
    })
    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthResponse> refresh(
            @Parameter(
                    description = "Refresh token request containing the refresh token",
                    required = true,
                    content = @Content(
                            schema = @Schema(implementation = RefreshTokenRequest.class),
                            examples = @ExampleObject(value = "{\"refreshToken\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\"}")
                    )
            )
            @Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        return ResponseEntity.ok(authService.refreshToken(refreshTokenRequest));
    }

    @Operation(
            summary = "Request password reset",
            description = "Initiates a password reset process by sending a reset token to the user's email."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Password reset request processed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = PasswordResetDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid or missing email",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Email is required\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "404",
                    description = "User with the provided email not found",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"User not found\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error (e.g., email sending failed)",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Server error occurred\"}")
                    )
            )
    })
    @PostMapping("/forgot-password")
    public ResponseEntity<PasswordResetDto> forgotPassword(
            @Parameter(
                    description = "Request body containing the user's email",
                    required = true,
                    content = @Content(
                            examples = @ExampleObject(value = "{\"email\": \"user@example.com\"}")
                    )
            )
            @RequestBody Map<String, String> request) {
        return ResponseEntity.ok(authService.forgotPassword(request.get("email")));
    }

    @Operation(
            summary = "Validate password reset token",
            description = "Validates a password reset token and invalidates it if valid."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Reset token validated successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = PasswordResetDto.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Missing or invalid token",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Token is required\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid or expired token",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Invalid or expired token\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Server error occurred\"}")
                    )
            )
    })
    @PostMapping("/validate-reset-token")
    public ResponseEntity<PasswordResetDto> validateResetToken(
            @Parameter(
                    description = "Password reset token to validate",
                    required = true,
                    example = "abc123-token-example"
            )
            @RequestParam String token) {
        return ResponseEntity.ok(authService.validateAndInvalidateResetToken(token));
    }

    @Operation(
            summary = "Reset user password",
            description = "Resets the user's password using a valid reset token."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Password reset successfully",
                    content = @Content(mediaType = "application/json")
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid or missing token/password",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Token and password are required\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "401",
                    description = "Invalid or expired reset token",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Invalid or expired token\"}")
                    )
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = String.class),
                            examples = @ExampleObject(value = "{\"error\": \"Server error occurred\"}")
                    )
            )
    })
    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(
            @Parameter(
                    description = "Request containing the reset token and new password",
                    required = true,
                    content = @Content(
                            schema = @Schema(implementation = ResetPasswordRequest.class),
                            examples = @ExampleObject(value = "{\"token\": \"abc123-token-example\", \"password\": \"NewPassword123!\"}")
                    )
            )
            @Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
        authService.resetPassword(resetPasswordRequest.token(), resetPasswordRequest.password());
        return ResponseEntity.ok().build();
    }
}

