package com.cbcode.dealertasksV1.ExceptionsConfig;

public class RoleNotFoundException extends RuntimeException {
    public RoleNotFoundException(String message) {
        super(message);
    }
}
