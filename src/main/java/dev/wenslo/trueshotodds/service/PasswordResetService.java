package dev.wenslo.trueshotodds.service;

import dev.wenslo.trueshotodds.entity.PasswordResetToken;
import dev.wenslo.trueshotodds.entity.User;
import dev.wenslo.trueshotodds.exception.UserNotFoundException;
import dev.wenslo.trueshotodds.repository.PasswordResetTokenRepository;
import dev.wenslo.trueshotodds.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final EmailService emailService;
    private final UserService userService;

    @Value("${app.security.password-reset-token-expiration-hours:1}")
    private int tokenExpirationHours;

    @Transactional
    public void initatePasswordReset(String email) {
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        tokenRepository.invalidateAllUserTokens(user.getId());

        String token = UUID.randomUUID().toString();
        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setUser(user);
        resetToken.setToken(token);
        resetToken.setExpiresAt(LocalDateTime.now().plusHours(tokenExpirationHours));

        tokenRepository.save(resetToken);

        emailService.sendPasswordResetEmail(user.getEmail(), user.getFullName(), token);

        log.info("Password reset initiated for user: {}", email);
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = tokenRepository.findByTokenAndUsedFalse(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired reset token"));

        if (!resetToken.isValid()) {
            throw new IllegalArgumentException("Reset token is invalid or expired");
        }

        userService.updatePassword(resetToken.getUser().getId(), newPassword);

        resetToken.markAsUsed();
        tokenRepository.save(resetToken);

        log.info("Password reset completed for user: {}", resetToken.getUser().getEmail());
    }

    @Transactional
    @Scheduled(cron = "0 0 2 * * ?")
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        tokenRepository.deleteExpiredTokens(now);
        log.info("Cleaned up expired password reset tokens");
    }
}