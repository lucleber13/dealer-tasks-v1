package com.cbcode.dealertasksV1.Users.security.DTOs.Request;

public record ResetPasswordRequest(String token, String password) {
}
