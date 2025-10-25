package dev.wenslo.trueshotodds.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.wenslo.trueshotodds.dto.response.AuthResponse;
import dev.wenslo.trueshotodds.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();

        log.info("User {} successfully authenticated", userPrincipal.getEmail());

        // Update last login and reset failed attempts directly using repository
        userRepository.updateLastLoginAndResetFailedAttempts(userPrincipal.getUserId(), LocalDateTime.now());

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        AuthResponse authResponse = AuthResponse.success(
            "Login successful"
        );

        objectMapper.writeValue(response.getWriter(), authResponse);
    }
}