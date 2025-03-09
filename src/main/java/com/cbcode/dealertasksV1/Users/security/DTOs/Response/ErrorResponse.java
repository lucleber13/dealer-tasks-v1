package com.cbcode.dealertasksV1.Users.security.DTOs.Response;

public record ErrorResponse(String error, String code, String message, String status, String timestamp, String path) {
}
