package com.cbcode.dealertasksV1.Users.security.DTOs.Request;

public record UserUpdateRequest(String firstName, String lastName, String email, String password) {
}
