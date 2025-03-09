package com.cbcode.dealertasksV1.ExceptionsConfig;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String message) {
      super(message);
    }
}
