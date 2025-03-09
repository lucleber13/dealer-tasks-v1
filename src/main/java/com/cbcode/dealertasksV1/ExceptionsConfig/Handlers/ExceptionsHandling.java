package com.cbcode.dealertasksV1.ExceptionsConfig.Handlers;

import com.cbcode.dealertasksV1.ExceptionsConfig.*;
import com.cbcode.dealertasksV1.Users.security.DTOs.Response.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.jetbrains.annotations.NotNull;

@RestControllerAdvice
public class ExceptionsHandling {

    private static final String MESSAGE = "message";
    private static final String EXCEPTION = "exception";
    private static final String STATUS = "status";
    private static final String ERROR = "error";
    private static final String TIMESTAMP = "timestamp";
    private static final String PATH = "path";

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        String errorMessage = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));
        return ResponseEntity
                .badRequest()
                .body(new ApiResponse(false, errorMessage));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(ex.getMessage());
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(UserNotFoundException.class)
    public Map<String, String> handleUserNotFoundException1(@NotNull UserNotFoundException ex) {
        Map<String, String> errors = new HashMap<>();
        errors.put(MESSAGE, ex.getMessage());
        return errors;
    }

    @ResponseStatus(HttpStatus.CONFLICT)
    @ExceptionHandler(UserAlreadyExistsException.class)
    public Map<String, String> handleUserAlreadyExistsException(@NotNull UserAlreadyExistsException ex) {
        Map<String, String> errors = new HashMap<>();
        errors.put(MESSAGE, ex.getMessage());
        return errors;
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(RoleNotFoundException.class)
    public Map<String, String> handleRoleNotFoundException(@NotNull RoleNotFoundException ex) {
        Map<String, String> errors = new HashMap<>();
        errors.put(MESSAGE, ex.getMessage());
        return errors;
    }

    @ResponseStatus(HttpStatus.PARTIAL_CONTENT)
    @ExceptionHandler(PasswordTooShortException.class)
    public Map<String, String> handlePasswordTooShortException(@NotNull PasswordTooShortException ex) {
        Map<String, String> errors = new HashMap<>();
        errors.put(MESSAGE, ex.getMessage());
        return errors;
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(UserCreationException.class)
    public Map<String, String> handleUserCreationException(@NotNull UserCreationException ex) {
        Map<String, String> errors = new HashMap<>();
        errors.put(MESSAGE, ex.getMessage());
        return errors;
    }



}
