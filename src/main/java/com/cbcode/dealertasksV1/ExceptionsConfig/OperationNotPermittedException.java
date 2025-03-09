package com.cbcode.dealertasksV1.ExceptionsConfig;

public class OperationNotPermittedException extends RuntimeException {
    public OperationNotPermittedException(String adminPrivilegesRequired) {
        super(adminPrivilegesRequired);
    }
}
