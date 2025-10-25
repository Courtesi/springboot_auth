package dev.wenslo.trueshotodds.controller;

import dev.wenslo.trueshotodds.dto.request.ConfirmDeleteAccountRequest;
import dev.wenslo.trueshotodds.dto.request.DeleteAccountRequest;
import dev.wenslo.trueshotodds.dto.request.UpdatePreferencesRequest;
import dev.wenslo.trueshotodds.dto.response.DeleteAccountResponse;
import dev.wenslo.trueshotodds.dto.response.ProfileResponse;
import dev.wenslo.trueshotodds.security.CustomUserPrincipal;
import dev.wenslo.trueshotodds.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/profile")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Profile", description = "User profile management endpoints")
public class ProfileController {

    private final UserService userService;

    @GetMapping
    @Operation(summary = "Get user profile", description = "Returns detailed user profile information")
    public ResponseEntity<ProfileResponse> getProfile(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }

        CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
        // Fetch fresh user profile data from database
        ProfileResponse profile = userService.getUserProfile(userPrincipal.getUserId());

        return ResponseEntity.ok(profile);
    }

    @PutMapping("/preferences")
    @Operation(summary = "Update user preferences", description = "Updates user notification and email preferences")
    public ResponseEntity<ProfileResponse> updatePreferences(@Valid @RequestBody UpdatePreferencesRequest request,
                                                            Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }

        CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();

        try {
            // Update preferences and return fresh profile data
            ProfileResponse updatedProfile = userService.updateUserPreferences(userPrincipal.getUserId(), request);
            return ResponseEntity.ok(updatedProfile);
        } catch (Exception e) {
            log.error("Failed to update preferences for user: {}", userPrincipal.getUserId(), e);
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/delete-account/request")
    @Operation(summary = "Request account deletion", description = "Initiates account deletion process by sending confirmation email")
    public ResponseEntity<DeleteAccountResponse> requestAccountDeletion(@Valid @RequestBody DeleteAccountRequest request,
                                                                      Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(401)
                    .body(DeleteAccountResponse.error("Authentication required"));
        }

        log.info("request: {}", request.toString());

        CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
        ProfileResponse profile = userService.getUserProfile(userPrincipal.getUserId());
        if (profile.getHasPassword() && (request.getCurrentPassword() == null || request.getCurrentPassword().trim().isEmpty())) {
            return ResponseEntity.badRequest()
                    .body(DeleteAccountResponse.error("Password is required for account deletion"));
        }
        if (profile.getIsOAuth2User() && !profile.getHasPassword() && request.getCurrentPassword() != null && !request.getCurrentPassword().trim().isEmpty()) {
            return ResponseEntity.badRequest()
                    .body(DeleteAccountResponse.error("OAuth2 users do not need to provide a password"));
        }

        log.info("userEmail: {}", userPrincipal.getEmail());

        try {
            userService.requestAccountDeletion(userPrincipal.getUserId(), request.getCurrentPassword());
            return ResponseEntity.ok(DeleteAccountResponse.success(
                    "Account deletion confirmation email sent. Please check your email and click the confirmation link to permanently delete your account."));
        } catch (IllegalArgumentException e) {
            log.warn("Invalid deletion request for user: {} - {}", userPrincipal.getUserId(), e.getMessage());
            return ResponseEntity.badRequest()
                    .body(DeleteAccountResponse.error(e.getMessage()));
        } catch (IllegalStateException e) {
            log.warn("Duplicate deletion request for user: {} - {}", userPrincipal.getUserId(), e.getMessage());
            return ResponseEntity.badRequest()
                    .body(DeleteAccountResponse.error(e.getMessage()));
        } catch (Exception e) {
            log.error("Failed to request account deletion for user: {} - {}", userPrincipal.getUserId(), e.getMessage());
            return ResponseEntity.internalServerError()
                    .body(DeleteAccountResponse.error("Failed to process deletion request. Please try again later."));
        }
    }

    @PostMapping("/delete-account/confirm")
    @Operation(summary = "Confirm account deletion", description = "Permanently deletes the account using confirmation token")
    public ResponseEntity<DeleteAccountResponse> confirmAccountDeletion(@Valid @RequestBody ConfirmDeleteAccountRequest request) {
        try {
            userService.confirmAccountDeletion(request.getToken());
            return ResponseEntity.ok(DeleteAccountResponse.success(
                    "Your account has been permanently deleted. We're sorry to see you go."));
        } catch (IllegalArgumentException e) {
            log.warn("Invalid deletion token: {} - {}", request.getToken(), e.getMessage());
            return ResponseEntity.badRequest()
                    .body(DeleteAccountResponse.error("Invalid or expired deletion token. Please request a new deletion confirmation."));
        } catch (Exception e) {
            log.error("Failed to confirm account deletion for token: {} - {}", request.getToken(), e.getMessage());
            return ResponseEntity.internalServerError()
                    .body(DeleteAccountResponse.error("Account deletion failed. Please try again or contact support."));
        }
    }
}