package com.cbcode.dealertasksV1.ExceptionsConfig;

public class TokenExpiredException extends RuntimeException {
    public TokenExpiredException(String message) {
        super(message);
    }
}
