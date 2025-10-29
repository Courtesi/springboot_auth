package dev.wenslo.trueshotodds.service;

import dev.wenslo.trueshotodds.dto.request.RegisterRequest;
import dev.wenslo.trueshotodds.dto.request.UpdatePreferencesRequest;
import dev.wenslo.trueshotodds.dto.response.ProfileResponse;
import dev.wenslo.trueshotodds.entity.*;
import dev.wenslo.trueshotodds.exception.UserNotFoundException;
import dev.wenslo.trueshotodds.repository.DeleteAccountTokenRepository;
import dev.wenslo.trueshotodds.repository.PasswordResetTokenRepository;
import dev.wenslo.trueshotodds.repository.UserPreferencesRepository;
import dev.wenslo.trueshotodds.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final UserPreferencesRepository preferencesRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final DeleteAccountTokenRepository deleteAccountTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Value("${REQUIRE_EMAIL_VERIFICATION}")
    private boolean requireEmailVerification;

    public UserService(UserRepository userRepository,
                      UserPreferencesRepository preferencesRepository,
                      PasswordResetTokenRepository tokenRepository,
                      DeleteAccountTokenRepository deleteAccountTokenRepository,
                      PasswordEncoder passwordEncoder,
                      EmailService emailService) {
        this.userRepository = userRepository;
        this.preferencesRepository = preferencesRepository;
        this.tokenRepository = tokenRepository;
        this.deleteAccountTokenRepository = deleteAccountTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        System.out.println("requireEmailVerification: " + requireEmailVerification);
    }

    @Value("${app.security.max-failed-login-attempts:5}")
    private int maxFailedLoginAttempts;

    @Value("${app.security.account-lockout-minutes:15}")
    private int accountLockoutMinutes;

    @Transactional
    public User registerUser(RegisterRequest request) {
        log.info("Registering user with email: {}", request.getEmail());

        if (userRepository.existsByEmailIgnoreCase(request.getEmail())) {
            // Send existing account notification instead of throwing exception
            Optional<User> existingUser = userRepository.findByEmailIgnoreCase(request.getEmail());
            if (existingUser.isPresent()) {
                emailService.sendExistingAccountNotification(existingUser.get().getEmail(), existingUser.get().getFullName());
                log.info("Existing account notification sent for email: {}", request.getEmail());
            }
            // Return null to indicate no new user was created (caller should handle this)
            return null;
        }

        User user = new User();
        user.setEmail(request.getEmail().toLowerCase());
        user.setFullName(request.getFullName());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setStatus(UserStatus.ACTIVE);

        if (requireEmailVerification) {
            user.setEmailVerificationToken(UUID.randomUUID().toString());
            user.setEmailVerificationTokenExpiresAt(LocalDateTime.now().plusHours(24));
        }

        user = userRepository.save(user);

        createDefaultPreferences(user);

        if (requireEmailVerification) {
            emailService.sendEmailVerification(user.getEmail(), user.getFullName(), user.getEmailVerificationToken());
        }

        log.info("User registered successfully with ID: {}", user.getId());
        return user;
    }

    @Transactional(readOnly = true)
    public ProfileResponse getUserProfile(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        return buildProfileResponse(user);
    }

    @Transactional(readOnly = true)
    public ProfileResponse getUserProfileByEmail(String email) {
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        return buildProfileResponse(user);
    }

    @Transactional
    public void updateLastLoginAndResetFailedAttempts(String userId, LocalDateTime lastLoginAt) {
        userRepository.updateLastLoginAndResetFailedAttempts(userId, lastLoginAt);
        log.info("Updated last login and reset failed attempts for user ID: {}", userId);
    }

    @Transactional
    public void handleFailedLoginAttempt(String email) {
        Optional<User> userOptional = userRepository.findByEmailIgnoreCase(email);
        if (userOptional.isEmpty()) {
            return;
        }

        User user = userOptional.get();
        int currentAttempts = user.getFailedLoginAttempts() + 1;

        userRepository.incrementFailedLoginAttempts(email);

        if (currentAttempts >= maxFailedLoginAttempts) {
            LocalDateTime lockoutTime = LocalDateTime.now().plusMinutes(accountLockoutMinutes);
            userRepository.lockUserAccount(email, lockoutTime);
            log.warn("Account locked for user: {} due to {} failed login attempts", email, currentAttempts);
        }

        log.info("Failed login attempt {} for user: {}", currentAttempts, email);
    }

    @Transactional
    public void verifyEmail(String token) {
        User user = userRepository.findByEmailVerificationToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid verification token"));

        if (user.getEmailVerificationTokenExpiresAt().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Verification token has expired");
        }

        userRepository.verifyUserEmail(token, UserStatus.ACTIVE);
        log.info("Email verified for user: {}", user.getEmail());
    }

    @Transactional
    public void updatePassword(String userId, String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + userId));

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        tokenRepository.invalidateAllUserTokens(userId);

        log.info("Password updated for user ID: {}", userId);
    }

    @Transactional
    public ProfileResponse updateUserPreferences(String userId, UpdatePreferencesRequest request) {
        UserPreferences preferences = preferencesRepository.findByUserId(userId)
                .orElseThrow(() -> new UserNotFoundException("User preferences not found"));

        if (request.getNotifications() != null) {
            preferences.setNotifications(request.getNotifications());
        }
        if (request.getEmailUpdates() != null) {
            preferences.setEmailUpdates(request.getEmailUpdates());
        }

        preferencesRepository.save(preferences);
        log.info("Updated preferences for user ID: {}", userId);

        return getUserProfile(userId);
    }

    private void createDefaultPreferences(User user) {
        UserPreferences preferences = new UserPreferences();
        preferences.setUser(user);
        preferences.setNotifications(true);
        preferences.setEmailUpdates(true);
        preferencesRepository.save(preferences);
    }

    private ProfileResponse buildProfileResponse(User user) {
        ProfileResponse response = new ProfileResponse();
        response.setEmail(user.getEmail());
        response.setFullName(user.getFullName());
        response.setCreatedAt(formatDateTime(user.getCreatedAt()));
        response.setLastLoginAt(formatDateTime(user.getLastLoginAt()));
        response.setOauthProvider(user.getOauthProvider());
        response.setProfilePictureUrl(user.getProfilePictureUrl());
        response.setIsOAuth2User(user.isOAuth2User());
        response.setHasPassword(user.isEmailPasswordUser());

        UserPreferences preferences = preferencesRepository.findByUserId(user.getId()).orElse(null);
        if (preferences != null) {
            ProfileResponse.PreferencesResponse prefResponse = new ProfileResponse.PreferencesResponse();
            prefResponse.setNotifications(preferences.getNotifications());
            prefResponse.setEmailUpdates(preferences.getEmailUpdates());
            response.setPreferences(prefResponse);
        }

        return response;
    }

    @Transactional(readOnly = true)
    public boolean verifyCurrentPassword(String userId, String currentPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + userId));

        return passwordEncoder.matches(currentPassword, user.getPassword());
    }

    @Transactional
    public void updateLastLogin(String userId) {
        userRepository.updateLastLoginAndResetFailedAttempts(userId, LocalDateTime.now());
        log.debug("Updated last login time for user ID: {}", userId);
    }

    @Transactional
    public void resendVerificationEmail(String email) {
        log.info("Processing resend verification request for email: {}", email);

        Optional<User> userOptional = userRepository.findByEmailIgnoreCase(email);

        if (userOptional.isEmpty()) {
            // User doesn't exist - log but don't reveal this to caller
            log.info("Resend verification requested for non-existent email: {}", email);
            return; // Silently return - caller gets same success message
        }

        User user = userOptional.get();

        // Check if user is already verified
        if (user.getStatus() == UserStatus.ACTIVE) {
            // Already verified - log but don't reveal this to caller
            log.info("Resend verification requested for already verified email: {}", email);
            // Optionally send "account already active" email here
            emailService.sendAccountAlreadyActiveNotification(user.getEmail(), user.getFullName());
            return; // Silently return - caller gets same success message
        }

        // Check if user is in wrong status (locked, suspended, etc.)
        if (user.getStatus() != UserStatus.PENDING_VERIFICATION) {
            log.warn("Resend verification requested for user in status: {} for email: {}",
                    user.getStatus(), email);
            return; // Silently return - don't reveal account status
        }

        // Rate limiting check (prevent spam)
        if (user.getEmailVerificationTokenExpiresAt() != null &&
            user.getEmailVerificationTokenExpiresAt().isAfter(LocalDateTime.now().plusMinutes(5))) {
            log.info("Resend verification rate limited for email: {} - recent token still valid", email);
            return; // Silently return - don't reveal rate limiting
        }

        // Generate new verification token and invalidate old one
        user.setEmailVerificationToken(UUID.randomUUID().toString());
        user.setEmailVerificationTokenExpiresAt(LocalDateTime.now().plusHours(24));
        userRepository.save(user);

        // Send new verification email
        emailService.sendEmailVerification(user.getEmail(), user.getFullName(), user.getEmailVerificationToken());

        log.info("New verification email sent for user: {}", email);
    }

    private String formatDateTime(LocalDateTime dateTime) {
        if (dateTime == null) {
            return null;
        }
        return dateTime.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
    }

    // Stripe-related methods for webhook handlers

    @Transactional(readOnly = true)
    public User findUserById(String userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found with ID: " + userId));
    }

    // Account deletion methods

    @Transactional
    public String requestAccountDeletion(String userId, String currentPassword) {
        User user = findUserById(userId);

        // Verify current password (only for email/password users)
        if (user.isEmailPasswordUser()) {
            if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
                throw new IllegalArgumentException("Invalid current password");
            }
        } else if (user.isOAuth2User()) {
            // OAuth2-only users don't need password verification
            if (currentPassword != null && !currentPassword.trim().isEmpty()) {
                throw new IllegalArgumentException("OAuth2 users do not have passwords. Leave password field empty.");
            }
        } else {
            throw new IllegalStateException("User has neither password nor OAuth2 provider configured");
        }

        // Check if there's already a valid token (prevent spam)
        long existingTokens = deleteAccountTokenRepository.countValidTokensForUser(userId, LocalDateTime.now());
        if (existingTokens > 0) {
            throw new IllegalStateException("A deletion request is already pending. Please check your email.");
        }

        // Generate deletion token
        DeleteAccountToken token = new DeleteAccountToken();
        token.setUser(user);
        token.setToken(UUID.randomUUID().toString());
        token.setExpiresAt(LocalDateTime.now().plusHours(1)); // 1 hour expiry

        deleteAccountTokenRepository.save(token);

        // Send confirmation email
        emailService.sendAccountDeletionConfirmation(user.getEmail(), user.getFullName(), token.getToken());

        log.info("Account deletion requested for user ID: {}", userId);
        return token.getToken();
    }

    @Transactional
    public void confirmAccountDeletion(String token) {
        // Find and validate token
        DeleteAccountToken deleteToken = deleteAccountTokenRepository.findValidToken(token, LocalDateTime.now())
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired deletion token"));

        User user = deleteToken.getUser();
        String userId = user.getId();
        String userEmail = user.getEmail();
        String userName = user.getFullName();

        log.info("Starting account deletion process for user ID: {}", userId);

        try {
            // Mark token as used
            deleteToken.markAsUsed();
            deleteAccountTokenRepository.save(deleteToken);

            // 2. Delete related data in correct order
            deleteAccountTokenRepository.deleteAllByUserId(userId);  // Delete all tokens for this user
            tokenRepository.deleteAllByUserId(userId);               // Delete password reset tokens

            // Delete user preferences (one-to-one)
            if (user.getPreferences() != null) {
                preferencesRepository.delete(user.getPreferences());
            }

            // 3. Delete user (this will cascade delete user_roles)
            userRepository.delete(user);

            // 4. Send deletion confirmation email
            emailService.sendAccountDeletionCompleted(userEmail, userName);

            log.info("Account deletion completed successfully for user ID: {}", userId);

        } catch (Exception e) {
            log.error("Account deletion failed for user ID: {}", userId, e);
            throw new RuntimeException("Account deletion failed: " + e.getMessage(), e);
        }
    }

    @Transactional(readOnly = true)
    public Optional<DeleteAccountToken> findValidDeletionToken(String token) {
        return deleteAccountTokenRepository.findValidToken(token, LocalDateTime.now());
    }

    @Transactional
    public void cleanupExpiredDeletionTokens() {
        LocalDateTime cutoffTime = LocalDateTime.now();
        deleteAccountTokenRepository.deleteExpiredTokens(cutoffTime);
        log.info("Cleaned up expired deletion tokens before: {}", cutoffTime);
    }

    @Transactional
    public User findOrCreateOAuth2User(String email, String fullName, String oauthId, String provider, String profilePictureUrl) {
        Optional<User> existingUser = userRepository.findByEmailIgnoreCase(email);

        if (existingUser.isPresent()) {
            User user = existingUser.get();

            // Update OAuth2 information for existing user
            if (user.getOauthProvider() == null) {
                user.setOauthProvider(provider);
                user.setOauthId(oauthId);
            }

            // Update profile picture and name if provided
            if (profilePictureUrl != null && !profilePictureUrl.trim().isEmpty()) {
                user.setProfilePictureUrl(profilePictureUrl);
            }

            // For OAuth2 users, we consider them email verified
            if (!user.isEmailVerified()) {
                user.setEmailVerified(true);
                user.setStatus(UserStatus.ACTIVE);
            }

            user = userRepository.save(user);
            log.info("Updated existing user {} with OAuth2 provider: {}", email, provider);
            return user;
        } else {
            // Create new OAuth2 user
            User newUser = new User();
            newUser.setEmail(email.toLowerCase());
            newUser.setFullName(fullName);
            newUser.setOauthProvider(provider);
            newUser.setOauthId(oauthId);
            newUser.setProfilePictureUrl(profilePictureUrl);
            newUser.setEmailVerified(true); // OAuth2 users have verified emails
            newUser.setStatus(UserStatus.ACTIVE);

            newUser = userRepository.save(newUser);

            // Create default subscription and preferences for new OAuth2 user
            createDefaultPreferences(newUser);

            log.info("Created new OAuth2 user with ID: {} for provider: {}", newUser.getId(), provider);
            return newUser;
        }
    }

    @Transactional(readOnly = true)
    public Optional<User> findByOAuth2Provider(String provider, String oauthId) {
        return userRepository.findByOauthProviderAndOauthId(provider, oauthId);
    }

    @Transactional
    public void unlinkOAuth2Provider(String userId) {
        User user = findUserById(userId);

        // Check if user has a password set, otherwise they won't be able to log in
        if (!user.isEmailPasswordUser()) {
            throw new IllegalStateException("Cannot unlink OAuth2 provider. User must have a password set first.");
        }

        user.setOauthProvider(null);
        user.setOauthId(null);
        user.setProfilePictureUrl(null);

        userRepository.save(user);
        log.info("Unlinked OAuth2 provider for user ID: {}", userId);
    }

    @Transactional
    public void linkOAuth2Provider(String userId, String oauthId, String provider, String profilePictureUrl) {
        User user = findUserById(userId);

        // Check if this OAuth2 account is already linked to another user
        Optional<User> existingOAuth2User = findByOAuth2Provider(provider, oauthId);
        if (existingOAuth2User.isPresent() && !existingOAuth2User.get().getId().equals(userId)) {
            throw new IllegalStateException("This " + provider + " account is already linked to another user.");
        }

        user.setOauthProvider(provider);
        user.setOauthId(oauthId);
        if (profilePictureUrl != null && !profilePictureUrl.trim().isEmpty()) {
            user.setProfilePictureUrl(profilePictureUrl);
        }

        userRepository.save(user);
        log.info("Linked OAuth2 provider {} for user ID: {}", provider, userId);
    }
}