package com.cbcode.dealertasksV1.ExceptionsConfig;

public class UserDeletionException extends RuntimeException {
    public UserDeletionException(String s) {
        super(s);
    }
}
