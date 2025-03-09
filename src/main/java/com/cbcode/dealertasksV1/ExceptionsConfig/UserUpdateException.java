package com.cbcode.dealertasksV1.ExceptionsConfig;

public class UserUpdateException extends RuntimeException {
    public UserUpdateException(String s) {
        super(s);
    }
}
