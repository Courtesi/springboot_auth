package dev.wenslo.trueshotodds.exception;

import dev.wenslo.trueshotodds.dto.response.AuthResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.session.SessionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @Autowired(required = false)
    private SessionRepository<?> sessionRepository;

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<AuthResponse> handleUserNotFoundException(UserNotFoundException ex) {
        log.warn("User not found: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(AuthResponse.error(ex.getMessage()));
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<AuthResponse> handleUserAlreadyExistsException(UserAlreadyExistsException ex) {
        log.warn("User already exists: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(AuthResponse.error(ex.getMessage()));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<AuthResponse> handleBadCredentialsException(BadCredentialsException ex) {
        log.warn("Bad credentials: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponse.error("Invalid email or password"));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<AuthResponse> handleAuthenticationException(AuthenticationException ex) {
        log.warn("Authentication failed: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponse.error("Authentication failed"));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<AuthResponse> handleAccessDeniedException(AccessDeniedException ex) {
        log.warn("Access denied: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(AuthResponse.error("Access denied"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, Object> response = new HashMap<>();
        Map<String, String> errors = new HashMap<>();

        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        response.put("success", false);
        response.put("message", "Validation failed");
        response.put("errors", errors);

        log.warn("Validation errors: {}", errors);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(BindException.class)
    public ResponseEntity<Map<String, Object>> handleBindException(BindException ex) {
        Map<String, Object> response = new HashMap<>();
        Map<String, String> errors = new HashMap<>();

        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        response.put("success", false);
        response.put("message", "Validation failed");
        response.put("errors", errors);

        log.warn("Binding errors: {}", errors);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<AuthResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
        log.warn("Illegal argument: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(AuthResponse.error(ex.getMessage()));
    }

    @ExceptionHandler(SerializationException.class)
    public ResponseEntity<AuthResponse> handleSerializationException(SerializationException ex, HttpServletRequest request) {
        log.error("Redis serialization error - clearing corrupted session", ex);

        // Clear the corrupted session to prevent cascading failures
        clearCorruptedSession(request);

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponse.error("Your session has expired. Please log in again."));
    }

    @ExceptionHandler(RedisConnectionFailureException.class)
    public ResponseEntity<AuthResponse> handleRedisConnectionFailure(RedisConnectionFailureException ex, HttpServletRequest request) {
        log.error("Redis connection failure - session storage unavailable", ex);

        // Clear local session since Redis is unavailable
        clearLocalSession(request);

        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(AuthResponse.error("Service temporarily unavailable. Please try again later."));
    }

    @ExceptionHandler(ClassCastException.class)
    public ResponseEntity<AuthResponse> handleClassCastException(ClassCastException ex, HttpServletRequest request) {
        // This often happens with corrupted authentication objects in sessions
        if (ex.getMessage() != null && ex.getMessage().contains("UserPrincipal")) {
            log.warn("Authentication object corruption detected - clearing session", ex);
            clearCorruptedSession(request);

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthResponse.error("Authentication error. Please log in again."));
        }

        // If it's not session-related, let the generic handler deal with it
        return handleGenericException(ex);
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<AuthResponse> handleNoResourceFound(NoResourceFoundException ex) {
        log.warn("Resource not found: {}", ex.getResourcePath());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(AuthResponse.error("Endpoint not found"));
    }


    private void clearCorruptedSession(HttpServletRequest request) {
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                String sessionId = session.getId();
                log.info("Invalidating corrupted session: {}", sessionId);

                // Invalidate local session
                session.invalidate();

                // Delete from Redis if session repository is available
                if (sessionRepository != null) {
                    try {
                        sessionRepository.deleteById(sessionId);
                        log.info("Successfully deleted corrupted session from Redis: {}", sessionId);
                    } catch (Exception e) {
                        log.warn("Failed to delete session from Redis: {}", sessionId, e);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error while clearing corrupted session", e);
        }
    }

    private void clearLocalSession(HttpServletRequest request) {
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
                log.info("Cleared local session due to Redis unavailability");
            }
        } catch (Exception e) {
            log.error("Error while clearing local session", e);
        }
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<AuthResponse> handleGenericException(Exception ex) {
        log.error("Unexpected error occurred: {}!! YIPPEE", ex.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(AuthResponse.error("An unexpected error occurred. Please try again later."));
    }
}