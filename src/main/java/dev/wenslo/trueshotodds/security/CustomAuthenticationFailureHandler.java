package dev.wenslo.trueshotodds.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.wenslo.trueshotodds.dto.response.AuthResponse;
import dev.wenslo.trueshotodds.entity.User;
import dev.wenslo.trueshotodds.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        String email = request.getParameter("email");
        log.warn("Authentication failed for user: {} - {}", email, exception.getMessage());

        String message;
        int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

        if (exception instanceof BadCredentialsException) {
            if (email != null) {
                handleFailedLoginAttempt(email);
            }
            message = "Invalid email or password";
        } else if (exception instanceof LockedException) {
            message = "Account is temporarily locked due to too many failed login attempts";
        } else if (exception instanceof DisabledException) {
            message = "Account is disabled. Please verify your email address.";
        } else if (exception instanceof UsernameNotFoundException) {
            message = "Invalid email or password";
        } else {
            message = "Authentication failed";
        }

        response.setStatus(statusCode);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        AuthResponse authResponse = AuthResponse.error(message);
        objectMapper.writeValue(response.getWriter(), authResponse);
    }

    @Transactional
    protected void handleFailedLoginAttempt(String email) {
        Optional<User> userOptional = userRepository.findByEmailIgnoreCase(email);
        if (userOptional.isEmpty()) {
            return;
        }

        User user = userOptional.get();
        int currentAttempts = user.getFailedLoginAttempts() + 1;

        userRepository.incrementFailedLoginAttempts(email);

        if (currentAttempts >= 5) { // Using default max failed attempts
            LocalDateTime lockoutTime = LocalDateTime.now().plusMinutes(15); // Using default lockout minutes
            userRepository.lockUserAccount(email, lockoutTime);
            log.warn("Account locked for user: {} due to {} failed login attempts", email, currentAttempts);
        }

        log.info("Failed login attempt {} for user: {}", currentAttempts, email);
    }
}