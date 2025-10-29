package dev.wenslo.trueshotodds.controller;

import dev.wenslo.trueshotodds.dto.request.*;
import dev.wenslo.trueshotodds.dto.response.AuthResponse;
import dev.wenslo.trueshotodds.dto.response.PasswordStrengthResponse;
import dev.wenslo.trueshotodds.dto.response.ProfileResponse;
import dev.wenslo.trueshotodds.dto.response.SessionStatusResponse;
import dev.wenslo.trueshotodds.entity.User;
import dev.wenslo.trueshotodds.security.CustomUserPrincipal;
import dev.wenslo.trueshotodds.service.PasswordResetService;
import dev.wenslo.trueshotodds.service.PasswordStrengthService;
import dev.wenslo.trueshotodds.service.RateLimitService;
import dev.wenslo.trueshotodds.service.UserService;
import dev.wenslo.trueshotodds.util.ClientIpUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "User authentication and session management endpoints")
public class AuthController {

    private final UserService userService;
    private final PasswordResetService passwordResetService;
    private final PasswordStrengthService passwordStrengthService;
    private final RateLimitService rateLimitService;
//    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    @Operation(summary = "Register a new user", description = "Creates a new user account and sends email verification")
    @ApiResponse(responseCode = "200", description = "User registered successfully")
    @ApiResponse(responseCode = "400", description = "Invalid request data")
    @ApiResponse(responseCode = "429", description = "Too many requests")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        try {
            String clientIp = ClientIpUtils.getClientIpAddress(httpRequest);

            // Check rate limit
            if (!rateLimitService.isAllowed(clientIp, RateLimitService.RateLimitType.REGISTRATION)) {
                log.warn("Registration rate limit exceeded for IP: {}", clientIp);
                return ResponseEntity.status(429)
                    .body(AuthResponse.error("Too many registration attempts. Please try again later."));
            }

            log.info("Registration attempt for email: {} from IP: {}", request.getEmail(), clientIp);

            if (!request.getPassword().equals(request.getConfirmPassword())) {
                return ResponseEntity.badRequest()
                        .body(AuthResponse.error("Passwords do not match"));
            }

            // Validate password strength
            PasswordStrengthService.PasswordValidationResult passwordValidation =
                passwordStrengthService.validatePassword(request.getPassword());

            if (!passwordValidation.isValid()) {
                return ResponseEntity.badRequest()
                        .body(AuthResponse.error("Password does not meet security requirements: " +
                            String.join(", ", passwordValidation.getErrors())));
            }

            User user = userService.registerUser(request);
            // Always return success response to prevent email enumeration
            // Whether user was created or already exists, we return the same message
            return ResponseEntity.ok(AuthResponse.success(
                "Registration successful. Please log in with your account now."
            ));
        } catch (Exception e) {
            log.error("Registration failed for email: {} with error: {}", request.getEmail(), e.getMessage());
            // Return generic success message even on error to prevent enumeration
            return ResponseEntity.ok(AuthResponse.success(
                "Registration successful. Please log in with your account now."
            ));
        }
    }

    @GetMapping("/verify-email")
    @Operation(summary = "Verify email address", description = "Verifies user email using verification token")
    public ResponseEntity<AuthResponse> verifyEmail(@RequestParam String token) {
        try {
            userService.verifyEmail(token);
            return ResponseEntity.ok(AuthResponse.success("Email verified successfully. You can now log in."));
        } catch (Exception e) {
            log.error("Email verification failed for token: {} with error: {}", token, e.getMessage());
            return ResponseEntity.badRequest()
                    .body(AuthResponse.error(e.getMessage()));
        }
    }

    @PostMapping("/resend-verification")
    @Operation(summary = "Resend email verification", description = "Resends verification email to user")
    @ApiResponse(responseCode = "200", description = "Verification email sent (if account exists)")
    @ApiResponse(responseCode = "429", description = "Too many requests")
    public ResponseEntity<AuthResponse> resendVerification(@Valid @RequestBody ResendVerificationRequest request, HttpServletRequest httpRequest) {
        try {
            String clientIp = ClientIpUtils.getClientIpAddress(httpRequest);

            // Check rate limit
            if (!rateLimitService.isAllowed(clientIp, RateLimitService.RateLimitType.RESEND_VERIFICATION)) {
                log.warn("Resend verification rate limit exceeded for IP: {}", clientIp);
                return ResponseEntity.status(429)
                        .body(AuthResponse.error("Too many verification email requests. Please try again later."));
            }

            log.info("Resend verification request for email: {} from IP: {}", request.getEmail(), clientIp);

            userService.resendVerificationEmail(request.getEmail());

            // Return success message even if email doesn't exist to prevent enumeration
            return ResponseEntity.ok(AuthResponse.success(
                    "If an account with this email exists and is not yet verified, a new verification email has been sent."
            ));
        } catch (Exception e) {
            log.error("Resend verification failed for email: {} with error: {}", request.getEmail(), e.getMessage());
            // Return same success message even on error to prevent enumeration
            return ResponseEntity.ok(AuthResponse.success(
                    "If an account with this email exists and is not yet verified, a new verification email has been sent."
            ));
        }
    }

    @PostMapping("/login")
    @Operation(summary = "User login", description = "Authenticates user and creates session")
    @ApiResponse(responseCode = "200", description = "Login successful")
    @ApiResponse(responseCode = "401", description = "Invalid credentials")
    @ApiResponse(responseCode = "429", description = "Too many requests")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request,
                                              HttpServletRequest httpRequest) {
        try {
            String clientIp = ClientIpUtils.getClientIpAddress(httpRequest);

            // Check rate limit
            if (!rateLimitService.isAllowed(clientIp, RateLimitService.RateLimitType.LOGIN)) {
                log.warn("Login rate limit exceeded for IP: {}", clientIp);
                return ResponseEntity.status(429)
                        .body(AuthResponse.error("Too many login attempts. Please try again later."));
            }

            log.info("Login attempt for email: {} from IP: {}", request.getEmail(), clientIp);

            // Create authentication token
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword());

            // Authenticate using Spring Security's AuthenticationManager
            Authentication authentication = authenticationManager.authenticate(authToken);

            // Get the authenticated user principal
            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();

            // Update last login time in database
            userService.updateLastLogin(userPrincipal.getUserId());

            // Create security context and set authentication
            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(securityContext);

            // Save security context to session - this will use our lightweight SessionUser
            HttpSession session = httpRequest.getSession(true);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);

            log.info("User {} successfully authenticated via JSON login", userPrincipal.getEmail());

            return ResponseEntity.ok(AuthResponse.success("Login successful"));

        } catch (AuthenticationException e) {
            log.warn("Authentication failed for email: {} - {}", request.getEmail(), e.getMessage());
            return ResponseEntity.status(401)
                    .body(AuthResponse.error("Invalid email or password"));
        } catch (Exception e) {
            log.error("Login failed for email: {}", request.getEmail(), e);
            return ResponseEntity.status(500)
                    .body(AuthResponse.error("An error occurred during login"));
        }
    }

    @GetMapping("/me")
    @Operation(summary = "Get current user profile", description = "Returns the profile of the currently authenticated user")
    public ResponseEntity<ProfileResponse> getCurrentUser(Authentication authentication) {
        try {
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(401).build();
            }

            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
            // Fetch fresh user data from database
            ProfileResponse profile = userService.getUserProfile(userPrincipal.getUserId());

            return ResponseEntity.ok(profile);
        } catch (Exception e) {
            log.error("getCurrentUser failed somehow", e);
            return ResponseEntity.badRequest().body(null);
        }
    }

    @PostMapping("/check-password-strength")
    @Operation(summary = "Check password strength", description = "Validates password strength and returns feedback")
    @ApiResponse(responseCode = "200", description = "Password strength analysis")
    public ResponseEntity<PasswordStrengthResponse> checkPasswordStrength(@Valid @RequestBody CheckPasswordStrengthRequest request) {
        try {
            PasswordStrengthService.PasswordValidationResult result =
                    passwordStrengthService.validatePassword(request.getPassword());

            PasswordStrengthResponse response = PasswordStrengthResponse.of(
                    result.isValid(),
                    result.getScore(),
                    result.getStrengthLevel(),
                    result.getErrors()
            );

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Password strength check failed", e);
            return ResponseEntity.badRequest()
                    .body(PasswordStrengthResponse.of(false, 0, "ERROR",
                            List.of("Unable to validate password strength")));
        }
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Request password reset", description = "Sends password reset email to user")
    @ApiResponse(responseCode = "429", description = "Too many requests")
    public ResponseEntity<AuthResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request, HttpServletRequest httpRequest) {
        try {
            String clientIp = ClientIpUtils.getClientIpAddress(httpRequest);

            // Check rate limit
            if (!rateLimitService.isAllowed(clientIp, RateLimitService.RateLimitType.PASSWORD_RESET)) {
                log.warn("Password reset rate limit exceeded for IP: {}", clientIp);
                return ResponseEntity.status(429)
                    .body(AuthResponse.error("Too many password reset requests. Please try again later."));
            }

            passwordResetService.initatePasswordReset(request.getEmail());
            return ResponseEntity.ok(AuthResponse.success(
                "If an account with this email exists, a password reset link has been sent."
            ));
        } catch (Exception e) {
            log.error("Password reset request failed for email: {}", request.getEmail(), e);
            return ResponseEntity.ok(AuthResponse.success(
                "If an account with this email exists, a password reset link has been sent."
            ));
        }
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset password", description = "Resets user password using reset token")
    public ResponseEntity<AuthResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try {
            if (!request.getNewPassword().equals(request.getConfirmPassword())) {
                return ResponseEntity.badRequest()
                        .body(AuthResponse.error("Passwords do not match"));
            }

            // Validate password strength
            PasswordStrengthService.PasswordValidationResult passwordValidation =
                passwordStrengthService.validatePassword(request.getNewPassword());

            if (!passwordValidation.isValid()) {
                return ResponseEntity.badRequest()
                        .body(AuthResponse.error("Password does not meet security requirements: " +
                            String.join(", ", passwordValidation.getErrors())));
            }

            passwordResetService.resetPassword(request.getToken(), request.getNewPassword());
            return ResponseEntity.ok(AuthResponse.success("Password reset successful. You can now log in with your new password."));
        } catch (Exception e) {
            log.error("Password reset failed for token: {}", request.getToken(), e);
            return ResponseEntity.badRequest()
                    .body(AuthResponse.error(e.getMessage()));
        }
    }

    @PutMapping("/change-password")
    @Operation(summary = "Change password", description = "Changes password for authenticated user")
    public ResponseEntity<AuthResponse> changePassword(@Valid @RequestBody ChangePasswordRequest request,
                                                       Authentication authentication) {
        try {

            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(401).build();
            }

            if (!request.getNewPassword().equals(request.getConfirmPassword())) {
                return ResponseEntity.badRequest()
                        .body(AuthResponse.error("New passwords do not match"));
            }

            // Validate password strength
            PasswordStrengthService.PasswordValidationResult passwordValidation =
                passwordStrengthService.validatePassword(request.getNewPassword());

            if (!passwordValidation.isValid()) {
                return ResponseEntity.badRequest()
                        .body(AuthResponse.error("Password does not meet security requirements: " +
                            String.join(", ", passwordValidation.getErrors())));
            }

            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();

            // Verify current password by checking against database (fresh data)
            if (!userService.verifyCurrentPassword(userPrincipal.getUserId(), request.getCurrentPassword())) {
                return ResponseEntity.badRequest()
                        .body(AuthResponse.error("Current password is incorrect"));
            }

            userService.updatePassword(userPrincipal.getUserId(), request.getNewPassword());
            return ResponseEntity.ok(AuthResponse.success("Password changed successfully"));
        } catch (Exception e) {
            log.error("Password change failed", e);
            return ResponseEntity.badRequest()
                    .body(AuthResponse.error("Failed to change password"));
        }
    }

    @GetMapping("/session")
    @Operation(summary = "Check session status", description = "Returns current session status and user information")
    public ResponseEntity<SessionStatusResponse> getSessionStatus(HttpServletRequest request,
                                                                 Authentication authentication) {
        HttpSession session = request.getSession(false);

        if (session == null || authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.ok(SessionStatusResponse.unauthenticated());
        }

        CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
        String expiresAt = Instant.ofEpochMilli(session.getLastAccessedTime() + session.getMaxInactiveInterval() * 1000L)
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime()
                .toString();

        return ResponseEntity.ok(SessionStatusResponse.authenticated(
                session.getId(),
                userPrincipal.getUserId(),
                userPrincipal.getEmail(),
                expiresAt
        ));
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout user", description = "Logs out the current user and invalidates session")
    public ResponseEntity<AuthResponse> logout() {
        log.info("user logged out");
        return ResponseEntity.ok(AuthResponse.success("Logout successful"));
    }

    @GetMapping("/session-expired")
    public ResponseEntity<AuthResponse> sessionExpired() {
        return ResponseEntity.status(401)
                .body(AuthResponse.error("Your session has expired. Please log in again."));
    }

    @GetMapping("/logout-success")
    public ResponseEntity<AuthResponse> logoutSuccess() {
        return ResponseEntity.ok(AuthResponse.success("You have been logged out successfully"));
    }

    @GetMapping("/oauth2/user-info")
    @Operation(summary = "Get OAuth2 user information", description = "Returns OAuth2 provider information for the current user")
    public ResponseEntity<Map<String, Object>> getOAuth2Info(Authentication authentication) {
        try {
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(401).build();
            }

            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
            ProfileResponse profile = userService.getUserProfile(userPrincipal.getUserId());

            Map<String, Object> oauth2Info = Map.of(
                "hasOAuth2Provider", profile.getOauthProvider() != null,
                "oauth2Provider", profile.getOauthProvider() != null ? profile.getOauthProvider() : "",
                "hasPassword", userService.findUserById(userPrincipal.getUserId()).isEmailPasswordUser(),
                "profilePictureUrl", profile.getProfilePictureUrl() != null ? profile.getProfilePictureUrl() : ""
            );

            return ResponseEntity.ok(oauth2Info);
        } catch (Exception e) {
            log.error("Failed to get OAuth2 info", e);
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/oauth2/unlink")
    @Operation(summary = "Unlink OAuth2 provider", description = "Removes OAuth2 provider link from user account")
    public ResponseEntity<AuthResponse> unlinkOAuth2Provider(Authentication authentication) {
        try {
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(401).build();
            }

            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
            userService.unlinkOAuth2Provider(userPrincipal.getUserId());

            return ResponseEntity.ok(AuthResponse.success("OAuth2 provider unlinked successfully"));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest()
                    .body(AuthResponse.error(e.getMessage()));
        } catch (Exception e) {
            log.error("Failed to unlink OAuth2 provider", e);
            return ResponseEntity.badRequest()
                    .body(AuthResponse.error("Failed to unlink OAuth2 provider"));
        }
    }
}