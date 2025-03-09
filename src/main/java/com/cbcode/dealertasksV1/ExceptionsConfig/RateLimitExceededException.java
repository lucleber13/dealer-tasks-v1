package com.cbcode.dealertasksV1.ExceptionsConfig;

public class RateLimitExceededException extends RuntimeException {
    public RateLimitExceededException(String tooManyRequests) {
        super(tooManyRequests);
    }
}
