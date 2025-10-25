package dev.wenslo.trueshotodds.service;

import dev.wenslo.trueshotodds.entity.Subscription;
import dev.wenslo.trueshotodds.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;

@Service
@Slf4j
@RequiredArgsConstructor
public class TierBetStreamService {

    private final TierWebSocketManager tierWebSocketManager;
    private final UserService userService;

    public SseEmitter createBetStream(String userId) {
        log.info("Creating tier-based bet stream for user: {}", userId);

        // Create SSE emitter with 30 minute timeout
        SseEmitter emitter = new SseEmitter(30 * 60 * 1000L);

        // Get user information for subscription type (optimized for minimal DB connection usage)
        UserService.BetStreamUserInfo userInfo = userService.getBetStreamUserInfo(userId);
        if (userInfo == null) {
            log.warn("User not found for bet stream: {}", userId);
            emitter.completeWithError(new RuntimeException("User not found"));
            return emitter;
        }

        String userTier = userInfo.getSubscriptionType();

        // Setup emitter callbacks with tier cleanup
        emitter.onCompletion(() -> {
            log.info("SSE connection completed for user: {} ({})", userId, userTier);
            tierWebSocketManager.removeUserFromTier(userId, userTier);
        });

        emitter.onTimeout(() -> {
            log.info("SSE connection timed out for user: {} ({})", userId, userTier);
            tierWebSocketManager.removeUserFromTier(userId, userTier);
        });

        emitter.onError((throwable) -> {
            log.error("SSE connection error for user: {} ({})", userId, userTier, throwable);
            tierWebSocketManager.removeUserFromTier(userId, userTier);
        });

        tierWebSocketManager.addUserToTier(userId, userTier, emitter);

        // Send initial connection message
        try {
            emitter.send(SseEmitter.event()
                    .name("connected")
                    .data(String.format("{\"status\":\"connected\",\"message\":\"Bet stream started\",\"tier\":\"%s\"}", userTier)));

            //TODO: DEBUG
            String lastMessage = tierWebSocketManager.getLastTierMessage(userTier);
            emitter.send(SseEmitter.event()
                    .name("bets")
                    .data(lastMessage));
            log.info("Sent initial 'connected' event to user: {} ({})", userId, userTier);
        } catch (IOException e) {
            log.error("Failed to send initial connection message to user: {}", userId, e);
            tierWebSocketManager.removeUserFromTier(userId, userTier);
            return emitter;
        }

        // Verify tier connection is active
        if (!tierWebSocketManager.isTierConnected(userTier)) {
            log.warn("Tier {} connection is not active for user: {}", userTier, userId);
            try {
                emitter.send(SseEmitter.event()
                        .name("warning")
                        .data("{\"status\":\"warning\",\"message\":\"Connecting to bet service...\"}"));
            } catch (IOException e) {
                log.error("Failed to send warning message to user: {}", userId, e);
            }
        }

        log.info("Tier-based bet stream created successfully for user: {} ({}). Total {} tier users: {}",
                userId, userTier, userTier, tierWebSocketManager.getTierUserCount(userTier));

        return emitter;
    }


    public int getActiveConnectionCount() {
        return tierWebSocketManager.getTotalUserCount();
    }

    public int getFreeUserCount() {
        return tierWebSocketManager.getTierUserCount("FREE");
    }

    public int getPremiumUserCount() {
        return tierWebSocketManager.getTierUserCount("PREMIUM");
    }

    public boolean isFreeTierConnected() {
        return tierWebSocketManager.isTierConnected("FREE");
    }

    public boolean isPremiumTierConnected() {
        return tierWebSocketManager.isTierConnected("PREMIUM");
    }

    public void shutdown() {
        log.info("Shutting down tier-based bet stream service");
        // TierWebSocketManager handles its own cleanup via @PreDestroy
    }
}