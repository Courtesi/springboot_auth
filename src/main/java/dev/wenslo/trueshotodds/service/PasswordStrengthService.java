package dev.wenslo.trueshotodds.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

@Service
@Slf4j
public class PasswordStrengthService {

    @Value("${app.security.password.min-length:8}")
    private int minLength;

    @Value("${app.security.password.max-length:128}")
    private int maxLength;

    @Value("${app.security.password.require-uppercase:true}")
    private boolean requireUppercase;

    @Value("${app.security.password.require-lowercase:true}")
    private boolean requireLowercase;

    @Value("${app.security.password.require-digits:true}")
    private boolean requireDigits;

    @Value("${app.security.password.require-special-chars:true}")
    private boolean requireSpecialChars;

    @Value("${app.security.password.min-special-chars:1}")
    private int minSpecialChars;

    @Value("${app.security.password.disallow-common-passwords:true}")
    private boolean disallowCommonPasswords;

    private static final Set<String> COMMON_PASSWORDS = Set.of(
        "password", "123456", "123456789", "qwerty", "abc123", "password123",
        "admin", "letmein", "welcome", "monkey", "1234567890", "password1",
        "123123", "12345678", "qwerty123", "000000", "1234567", "dragon",
        "sunshine", "princess", "azerty", "trustno1", "123321"
    );

    private static final Pattern UPPERCASE_PATTERN = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile("[a-z]");
    private static final Pattern DIGIT_PATTERN = Pattern.compile("[0-9]");
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?`~]");

    public PasswordValidationResult validatePassword(String password) {
        if (password == null) {
            return PasswordValidationResult.invalid("Password cannot be null");
        }

        List<String> errors = new ArrayList<>();
        int score = 0;

        // Length validation
        if (password.length() < minLength) {
            errors.add("Password must be at least %d characters long".formatted(minLength));
        } else {
            score += 20;
        }

        if (password.length() > maxLength) {
            errors.add("Password must not exceed %d characters".formatted(maxLength));
        }

        // Character type validation
        if (requireUppercase && !UPPERCASE_PATTERN.matcher(password).find()) {
            errors.add("Password must contain at least one uppercase letter");
        } else if (UPPERCASE_PATTERN.matcher(password).find()) {
            score += 15;
        }

        if (requireLowercase && !LOWERCASE_PATTERN.matcher(password).find()) {
            errors.add("Password must contain at least one lowercase letter");
        } else if (LOWERCASE_PATTERN.matcher(password).find()) {
            score += 15;
        }

        if (requireDigits && !DIGIT_PATTERN.matcher(password).find()) {
            errors.add("Password must contain at least one digit");
        } else if (DIGIT_PATTERN.matcher(password).find()) {
            score += 15;
        }

        if (requireSpecialChars) {
            long specialCharCount = password.chars()
                .filter(ch -> SPECIAL_CHAR_PATTERN.matcher(String.valueOf((char) ch)).matches())
                .count();

            if (specialCharCount < minSpecialChars) {
                errors.add("Password must contain at least %d special character(s)".formatted(minSpecialChars));
            } else {
                score += 15;
            }
        }

        // Common password check
        if (disallowCommonPasswords && COMMON_PASSWORDS.contains(password.toLowerCase())) {
            errors.add("Password is too common. Please choose a more unique password");
        }

        // Additional scoring for complexity
        if (password.length() >= 12) {
            score += 10;
        }
        if (password.length() >= 16) {
            score += 10;
        }

        // Check for repeated characters
        if (hasRepeatedCharacters(password)) {
            score -= 10;
            errors.add("Avoid using repeated characters in sequence");
        }

        // Normalize score to 0-100
        score = Math.max(0, Math.min(100, score));

        return errors.isEmpty()
            ? PasswordValidationResult.valid(score, getStrengthLevel(score))
            : PasswordValidationResult.invalid(errors);
    }

    private boolean hasRepeatedCharacters(String password) {
        for (int i = 0; i < password.length() - 2; i++) {
            if (password.charAt(i) == password.charAt(i + 1) &&
                password.charAt(i + 1) == password.charAt(i + 2)) {
                return true;
            }
        }
        return false;
    }

    private String getStrengthLevel(int score) {
        if (score >= 80) return "STRONG";
        if (score >= 60) return "MEDIUM";
        if (score >= 40) return "WEAK";
        return "VERY_WEAK";
    }

    public static class PasswordValidationResult {
        private final boolean valid;
        private final List<String> errors;
        private final int score;
        private final String strengthLevel;

        private PasswordValidationResult(boolean valid, List<String> errors, int score, String strengthLevel) {
            this.valid = valid;
            this.errors = errors != null ? errors : Collections.emptyList();
            this.score = score;
            this.strengthLevel = strengthLevel;
        }

        public static PasswordValidationResult valid(int score, String strengthLevel) {
            return new PasswordValidationResult(true, null, score, strengthLevel);
        }

        public static PasswordValidationResult invalid(String error) {
            return new PasswordValidationResult(false, List.of(error), 0, "INVALID");
        }

        public static PasswordValidationResult invalid(List<String> errors) {
            return new PasswordValidationResult(false, errors, 0, "INVALID");
        }

        public boolean isValid() {
            return valid;
        }

        public List<String> getErrors() {
            return errors;
        }

        public int getScore() {
            return score;
        }

        public String getStrengthLevel() {
            return strengthLevel;
        }
    }
}