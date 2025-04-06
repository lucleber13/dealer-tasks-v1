package com.cbcode.dealertasksV1.ExceptionsConfig;

public class CarMappingException extends RuntimeException {
    public CarMappingException(String message) {
        super(message);
    }

    public CarMappingException(String message, Throwable cause) {
        super(message, cause);
    }
}
