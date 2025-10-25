package dev.wenslo.trueshotodds.controller;

import dev.wenslo.trueshotodds.security.CustomUserPrincipal;
import dev.wenslo.trueshotodds.service.TierBetStreamService;
import dev.wenslo.trueshotodds.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
@RequestMapping("/api/bets")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Bets", description = "Live betting data streaming endpoints")
public class BetsController {

    private final TierBetStreamService tierBetStreamService;
    private final UserService userService;


    @GetMapping("/stream")
    @Operation(
        summary = "Stream live arbitrage bets",
        description = "Opens a Server-Sent Events (SSE) stream that continuously delivers arbitrage betting opportunities based on user's subscription level"
    )
    @ApiResponse(responseCode = "200", description = "SSE stream established successfully")
    @ApiResponse(responseCode = "401", description = "Authentication required")
    @ApiResponse(responseCode = "403", description = "Account locked or inactive")
    @ApiResponse(responseCode = "500", description = "Internal server error")
    public ResponseEntity<SseEmitter> streamBets(Authentication authentication) {
        try {
            // Check authentication
            if (authentication == null || !authentication.isAuthenticated()) {
                log.warn("Unauthenticated bet stream request");
                return ResponseEntity.status(401).build();
            }

            // Get user principal
            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
            String userId = userPrincipal.getUserId();
            String userEmail = userPrincipal.getEmail();

            log.info("Bet stream request from user: {} ({})", userEmail, userId);

            // Get essential user data for validation (optimized for minimal DB connection usage)
            UserService.BetStreamUserInfo userInfo = userService.getBetStreamUserInfo(userId);
            if (userInfo == null) {
                log.warn("User not found for bet stream: {}", userId);
                return ResponseEntity.status(401).build();
            }

            // Validate user can access bet stream
            if (!userInfo.canLogin()) {
                log.warn("Bet stream rejected for user {}: account locked, inactive, or unverified", userEmail);
                return ResponseEntity.status(403).build();
            }

            // Create and return SSE stream
            SseEmitter emitter = tierBetStreamService.createBetStream(userId);

            log.info("Bet stream established for user: {} ({})", userEmail, userId);
            log.info("SSE response headers will include: Content-Type=text/event-stream, Cache-Control=no-cache");
            return ResponseEntity.ok()
                    .header("Content-Type", "text/event-stream; charset=UTF-8")
                    .header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
                    .header("Pragma", "no-cache")
                    .header("Expires", "0")
                    .header("Connection", "keep-alive")
                    .header("X-Accel-Buffering", "no")
                    .body(emitter);

        } catch (Exception e) {
            log.error("Failed to create tier-based bet stream", e);
            return ResponseEntity.status(500).build();
        }
    }

    @GetMapping("/stream/status")
    @Operation(
        summary = "Get tier-based bet stream status",
        description = "Returns information about active tier-based bet streaming connections"
    )
    @ApiResponse(responseCode = "200", description = "Stream status retrieved successfully")
    @ApiResponse(responseCode = "401", description = "Authentication required")
    public ResponseEntity<Object> getStreamStatus(Authentication authentication) {
        try {
            // Check authentication
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(401).build();
            }

            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();

            // Return tier-based architecture status only
            return ResponseEntity.ok(java.util.Map.of(
                "userEmail", userPrincipal.getEmail(),
                "architecture", "tier-based",
                "totalUsers", tierBetStreamService.getActiveConnectionCount(),
                "endpoint", "/api/bets/stream"
            ));

        } catch (Exception e) {
            log.error("Failed to get stream status", e);
            return ResponseEntity.status(500).build();
        }
    }
}