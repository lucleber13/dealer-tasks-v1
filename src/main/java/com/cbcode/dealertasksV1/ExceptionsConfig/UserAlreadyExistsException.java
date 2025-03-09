package com.cbcode.dealertasksV1.ExceptionsConfig;

public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(String s) {
        super(s);
    }
}
