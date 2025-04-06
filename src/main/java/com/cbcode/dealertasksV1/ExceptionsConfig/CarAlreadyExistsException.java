package com.cbcode.dealertasksV1.ExceptionsConfig;

public class CarAlreadyExistsException extends RuntimeException {
    public CarAlreadyExistsException(String s) {
        super(s);
    }

    public CarAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }
}
