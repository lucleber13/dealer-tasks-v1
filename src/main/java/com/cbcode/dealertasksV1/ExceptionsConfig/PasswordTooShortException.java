package com.cbcode.dealertasksV1.ExceptionsConfig;

public class PasswordTooShortException extends RuntimeException {
    public PasswordTooShortException(String message) {
        super(message);
    }
}
