package com.cbcode.dealertasksV1.ExceptionsConfig;

public class UserCreationException extends RuntimeException {
    public UserCreationException(String s) {
        super(s);
    }
}
