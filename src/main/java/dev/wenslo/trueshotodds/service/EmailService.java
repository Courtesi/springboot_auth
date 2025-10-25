package dev.wenslo.trueshotodds.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${app.mail.from}")
    private String fromEmail;

    @Value("${app.mail.base-url}")
    private String baseUrl;

    @Async
    public void sendEmailVerification(String toEmail, String fullName, String token) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("TrueShotOdds - Verify Your Email Address");

            String verificationUrl = baseUrl + "/verify?token=" + token;
            String emailBody = """
                Hello %s,
                
                Thank you for registering with TrueShotOdds!
                
                Please verify your email address by clicking the link below:
                %s
                
                This link will expire in 24 hours.
                
                If you didn't create an account with us, please ignore this email.
                
                Best regards,
                The TrueShotOdds Team""".formatted(
                    fullName, verificationUrl
            );

            message.setText(emailBody);
            mailSender.send(message);

            log.info("Email verification sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send email verification to: {}", toEmail, e);
        }
    }

    @Async
    public void sendPasswordResetEmail(String toEmail, String fullName, String token) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("TrueShotOdds - Password Reset Request");

            String resetUrl = baseUrl + "/reset-password?token=" + token;
            String emailBody = """
                Hello %s,
                
                We received a request to reset your password for your TrueShotOdds account.
                
                Click the link below to reset your password:
                %s
                
                This link will expire in 1 hour for security reasons.
                
                If you didn't request a password reset, please ignore this email. Your password will remain unchanged.
                
                Best regards,
                The TrueShotOdds Team""".formatted(
                    fullName, resetUrl
            );

            message.setText(emailBody);
            mailSender.send(message);

            log.info("Password reset email sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send password reset email to: {}", toEmail, e);
        }
    }

    @Async
    public void sendPasswordChangedNotification(String toEmail, String fullName) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("TrueShotOdds - Password Changed Successfully");

            String emailBody = """
                Hello %s,
                
                Your password has been successfully changed for your TrueShotOdds account.
                
                If you didn't make this change, please contact our support team immediately.
                
                Best regards,
                The TrueShotOdds Team""".formatted(
                    fullName
            );

            message.setText(emailBody);
            mailSender.send(message);

            log.info("Password changed notification sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send password changed notification to: {}", toEmail, e);
        }
    }

    @Async
    public void sendExistingAccountNotification(String toEmail, String fullName) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("TrueShotOdds - Account Registration Attempt");

            String resetUrl = baseUrl + "/forgot-password";
            String emailBody = """
                Hello %s,
                
                We noticed someone tried to register an account with this email address, but you already have an existing account with TrueShotOdds.
                
                If you forgot your password, you can reset it by visiting:
                %s
                
                If you didn't attempt to register, you can safely ignore this email.
                
                Best regards,
                The TrueShotOdds Team""".formatted(
                    fullName, resetUrl
            );

            message.setText(emailBody);
            mailSender.send(message);

            log.info("Existing account notification sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send existing account notification to: {}", toEmail, e);
        }
    }

    @Async
    public void sendAccountAlreadyActiveNotification(String toEmail, String fullName) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("TrueShotOdds - Email Already Verified");

            String loginUrl = baseUrl + "/login";
            String emailBody = """
                Hello %s,
                
                We received a request to verify your email address, but your account is already verified and active.
                
                You can log in to your account at:
                %s
                
                If you're having trouble logging in, you can reset your password using the 'Forgot Password' link on the login page.
                
                If you didn't request email verification, you can safely ignore this email.
                
                Best regards,
                The TrueShotOdds Team""".formatted(
                    fullName, loginUrl
            );

            message.setText(emailBody);
            mailSender.send(message);

            log.info("Account already active notification sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send account already active notification to: {}", toEmail, e);
        }
    }

    @Async
    public void sendAccountDeletionConfirmation(String toEmail, String fullName, String token) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("TrueShotOdds - Confirm Account Deletion");

            String deleteUrl = baseUrl + "/delete-account?token=" + token;
            String emailBody = """
                Hello %s,
                
                We received a request to permanently delete your TrueShotOdds account.
                
                ⚠️ WARNING: This action is irreversible and will permanently delete:
                • Your account information
                • Your subscription and billing history
                • Your preferences and settings
                • All associated data
                
                If you're sure you want to proceed, click the link below to confirm deletion:
                %s
                
                This confirmation link will expire in 1 hour for security reasons.
                
                If you didn't request account deletion or have changed your mind, simply ignore this email. Your account will remain active.
                
                Best regards,
                The TrueShotOdds Team""".formatted(
                    fullName, deleteUrl
            );

            message.setText(emailBody);
            mailSender.send(message);

            log.info("Account deletion confirmation sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send account deletion confirmation to: {}", toEmail, e);
        }
    }

    @Async
    public void sendAccountDeletionCompleted(String toEmail, String fullName) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(toEmail);
            message.setSubject("TrueShotOdds - Account Deleted Successfully");

            String emailBody = """
                Hello %s,
                
                Your TrueShotOdds account has been permanently deleted as requested.
                
                All your data has been removed from our systems, including:
                • Account information
                • Subscription details
                • Preferences and settings
                • Billing history
                
                We're sorry to see you go! If you ever decide to return, you're always welcome to create a new account.
                
                Thank you for using TrueShotOdds.
                
                Best regards,
                The TrueShotOdds Team""".formatted(
                    fullName
            );

            message.setText(emailBody);
            mailSender.send(message);

            log.info("Account deletion completed notification sent to: {}", toEmail);
        } catch (Exception e) {
            log.error("Failed to send account deletion completed notification to: {}", toEmail, e);
        }
    }
}