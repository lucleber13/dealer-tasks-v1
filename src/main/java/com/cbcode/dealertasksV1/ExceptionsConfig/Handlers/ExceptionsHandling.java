package com.cbcode.dealertasksV1.ExceptionsConfig.Handlers;

import com.cbcode.dealertasksV1.ExceptionsConfig.*;
import com.cbcode.dealertasksV1.Users.security.DTOs.Response.ErrorResponse;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class ExceptionsHandling {

    private static final String MESSAGE = "message";
    private static final String CODE = "code";
    private static final String STATUS = "status";
    private static final String ERROR = "error";
    private static final String TIMESTAMP = "timestamp";
    private static final String PATH = "path";

    private @NotNull Map<String, String> buildErrorResponse(String error, String code, String message, @NotNull HttpStatus status, @NotNull WebRequest request) {
        Map<String, String> errors = new HashMap<>();
        errors.put(ERROR, error);
        errors.put(CODE, code);
        errors.put(MESSAGE, message);
        errors.put(STATUS, status.toString());
        errors.put(TIMESTAMP, Instant.now().toString());
        errors.put(PATH, request.getDescription(false).replace("uri=", ""));
        return errors;
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleMethodArgumentNotValidException(@NotNull MethodArgumentNotValidException ex, WebRequest request) {
        String errorMessage = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(buildErrorResponse("Validation failed", "VALIDATION_FAILED", errorMessage, HttpStatus.BAD_REQUEST, request));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(@NotNull IllegalArgumentException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Invalid argument",
                "INVALID_INPUT",
                ex.getMessage(),
                HttpStatus.BAD_REQUEST.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFoundException(@NotNull UserNotFoundException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Not found",
                "USER_NOT_FOUND",
                ex.getMessage(),
                HttpStatus.NOT_FOUND.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleUserAlreadyExistsException(@NotNull UserAlreadyExistsException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Conflict",
                "USER_ALREADY_EXISTS",
                ex.getMessage(),
                HttpStatus.CONFLICT.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleRoleNotFoundException(@NotNull RoleNotFoundException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Not found",
                "ROLE_NOT_FOUND",
                ex.getMessage(),
                HttpStatus.NOT_FOUND.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    @ExceptionHandler(PasswordTooShortException.class)
    public ResponseEntity<ErrorResponse> handlePasswordTooShortException(@NotNull PasswordTooShortException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Invalid password",
                "PASSWORD_TOO_SHORT",
                ex.getMessage(),
                HttpStatus.BAD_REQUEST.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(UserCreationException.class)
    public ResponseEntity<ErrorResponse> handleUserCreationException(@NotNull UserCreationException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Creation failed",
                "USER_CREATION_ERROR",
                ex.getMessage(),
                HttpStatus.BAD_REQUEST.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidTokenException(@NotNull InvalidTokenException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Invalid token",
                "INVALID_TOKEN",
                ex.getMessage(),
                HttpStatus.UNAUTHORIZED.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<ErrorResponse> handleTokenExpiredException(@NotNull TokenExpiredException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Token expired",
                "TOKEN_EXPIRED",
                ex.getMessage(),
                HttpStatus.UNAUTHORIZED.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<ErrorResponse> handleRateLimitExceededException(@NotNull RateLimitExceededException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Too many requests",
                "RATE_LIMIT_EXCEEDED",
                ex.getMessage(),
                HttpStatus.TOO_MANY_REQUESTS.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(response);
    }

    @ExceptionHandler(UserRetrievalException.class)
    public ResponseEntity<ErrorResponse> handleUserRetrievalException(@NotNull UserRetrievalException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Retrieval failed",
                "USER_RETRIEVAL_ERROR",
                ex.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    @ExceptionHandler(UserMappingException.class)
    public ResponseEntity<ErrorResponse> handleUserMappingException(@NotNull UserMappingException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Mapping failed",
                "USER_MAPPING_ERROR",
                ex.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    @ExceptionHandler(OperationNotPermittedException.class)
    public ResponseEntity<ErrorResponse> handleOperationNotPermittedException(@NotNull OperationNotPermittedException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Forbidden",
                "OPERATION_NOT_PERMITTED",
                ex.getMessage(),
                HttpStatus.FORBIDDEN.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    @ExceptionHandler(UserUpdateException.class)
    public ResponseEntity<ErrorResponse> handleUserUpdateException(@NotNull UserUpdateException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Update failed",
                "USER_UPDATE_ERROR",
                ex.getMessage(),
                HttpStatus.BAD_REQUEST.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(UserDeletionException.class)
    public ResponseEntity<ErrorResponse> handleUserDeletionException(@NotNull UserDeletionException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Deletion failed",
                "USER_DELETION_ERROR",
                ex.getMessage(),
                HttpStatus.BAD_REQUEST.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(CarAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleCarAlreadyExistsException(@NotNull CarAlreadyExistsException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Conflict",
                "CAR_ALREADY_EXISTS",
                ex.getMessage(),
                HttpStatus.CONFLICT.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    @ExceptionHandler(CarMappingException.class)
    public ResponseEntity<ErrorResponse> handleCarMappingException(@NotNull CarMappingException ex, @NotNull WebRequest request) {
        ErrorResponse response = new ErrorResponse(
                "Mapping failed",
                "CAR_MAPPING_ERROR",
                ex.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR.toString(),
                Instant.now().toString(),
                request.getDescription(false).replace("uri=", "")
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
