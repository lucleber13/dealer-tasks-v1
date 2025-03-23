package com.cbcode.dealertasksV1.Users.security.Impl;

import java.util.regex.Pattern;

public class ValidationUtil {

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    public static void validateId(Long id, String operation) {
        if (id == null || id <= 0) {
            throw new IllegalArgumentException("Invalid ID for " + id + " operation: " + operation);
        }
    }

    public static void validateEmail(String email) {
        if (email == null || email.trim().isEmpty() || !EMAIL_PATTERN.matcher(email.trim()).matches()) {
            throw new IllegalArgumentException("Invalid email format: " + email);
        }
    }
}
