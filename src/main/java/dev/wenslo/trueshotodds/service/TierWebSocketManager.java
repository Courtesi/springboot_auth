package dev.wenslo.trueshotodds.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

@Service
@Slf4j
@RequiredArgsConstructor
public class TierWebSocketManager {

    @Value("${app.websocket.python-service-url}")
    private String pythonServiceUrl;

    @Value("${app.websocket.api-key}")
    private String apiKey;

    private final ObjectMapper objectMapper;

    // Two persistent connections for tiers
    private WebSocketClient freeTierConnection;
    private WebSocketClient premiumTierConnection;

    // Track connection status
    private volatile boolean freeTierConnected = false;
    private volatile boolean premiumTierConnected = false;

    private String freeTierLastMessage = "";
    private String premiumTierLastMessage = "";

    // SSE connections grouped by tier: tier -> (userId -> SseEmitter)
    private final Map<String, SseEmitter> freeUserConnections = new ConcurrentHashMap<>();
    private final Map<String, SseEmitter> premiumUserConnections = new ConcurrentHashMap<>();

    @PostConstruct
    public void initializeTierConnections() {
        log.info("Initializing persistent tier-based WebSocket connections to Python service");

        // Initialize both tier connections on startup
        connectToTier("FREE");
        connectToTier("PREMIUM");
    }

    @PreDestroy
    public void cleanup() {
        log.info("Cleaning up tier WebSocket connections");

        if (freeTierConnection != null && !freeTierConnection.isClosed()) {
            freeTierConnection.close();
        }

        if (premiumTierConnection != null && !premiumTierConnection.isClosed()) {
            premiumTierConnection.close();
        }

        // Complete all SSE connections
        freeUserConnections.values().forEach(this::completeEmitterSafely);
        premiumUserConnections.values().forEach(this::completeEmitterSafely);

        freeUserConnections.clear();
        premiumUserConnections.clear();
    }

    private void connectToTier(String tier) {
        try {
            URI serverUri = new URI(pythonServiceUrl);
            WebSocketClient connection = new WebSocketClient(serverUri) {
                @Override
                public void onOpen(ServerHandshake handshake) {
                    log.info("Tier {} WebSocket connected to Python service at {}", tier, pythonServiceUrl);

                    if ("FREE".equals(tier)) {
                        freeTierConnected = true;
                    } else {
                        premiumTierConnected = true;
                    }

                    // Send authentication message for this tier
                    sendTierAuthMessage(this, tier);
                }

                @Override
                public void onMessage(String message) {
//                    log.info("Received {} tier data from Python service, message length: {}", tier, message.length());

                    // Broadcast to all users of this tier
                    setTierLastMessage(tier, message);
                    broadcastToTierUsers(tier, message);
                }

                @Override
                public void onClose(int code, String reason, boolean remote) {
                    log.warn("Tier {} WebSocket connection closed. Code: {}, Reason: {}, Remote: {}",
                            tier, code, reason, remote);

                    if ("FREE".equals(tier)) {
                        freeTierConnected = false;
                    } else {
                        premiumTierConnected = false;
                    }

                    // Schedule reconnection
                    scheduleReconnection(tier);
                }

                @Override
                public void onError(Exception ex) {
                    log.error("Error in tier {} WebSocket connection", tier, ex);

                    if ("FREE".equals(tier)) {
                        freeTierConnected = false;
                    } else {
                        premiumTierConnected = false;
                    }
                }
            };

            if ("FREE".equals(tier)) {
                freeTierConnection = connection;
            } else {
                premiumTierConnection = connection;
            }

            connection.connect();

        } catch (Exception e) {
            log.error("Failed to create tier {} WebSocket connection", tier, e);
        }
    }

    private void sendTierAuthMessage(WebSocketClient client, String tier) {
        try {
            String clientId = UUID.randomUUID().toString();
            Map<String, Object> authMessage = Map.of(
                "type", "auth",
                "api_key", apiKey,
                "client_id", clientId,
                "subscription_type", tier
            );

            String authJson = objectMapper.writeValueAsString(authMessage);
            client.send(authJson);
            log.info("Sent tier {} authentication to Python service", tier);

        } catch (Exception e) {
            log.error("Failed to send tier {} authentication", tier, e);
        }
    }

    private void setTierLastMessage(String tier, String message) {
        if ("FREE".equals(tier)) {
            freeTierLastMessage = message;
        } else {
            premiumTierLastMessage = message;
        }
    }

    private void broadcastToTierUsers(String tier, String message) {
        Map<String, SseEmitter> tierUsers = "FREE".equals(tier) ? freeUserConnections : premiumUserConnections;

//        log.info("Broadcasting to {} {} tier users", tierUsers.size(), tier);

        // Remove failed connections while broadcasting
        tierUsers.entrySet().removeIf(entry -> {
            String userId = entry.getKey();
            SseEmitter emitter = entry.getValue();

            try {
                emitter.send(SseEmitter.event()
                        .name("bets")
                        .data(message));
                return false; // Keep connection
            } catch (IOException e) {
                log.warn("Failed to send data to user {}, removing from {} tier", userId, tier);
                completeEmitterSafely(emitter);
                return true; // Remove connection
            }
        });
    }

    private void scheduleReconnection(String tier) {
        new Thread(() -> {
            try {
                Thread.sleep(5000); // Wait 5 seconds before reconnecting
                log.info("Attempting to reconnect tier {} WebSocket", tier);
                connectToTier(tier);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).start();
    }

    private void completeEmitterSafely(SseEmitter emitter) {
        try {
            emitter.complete();
        } catch (Exception e) {
            log.debug("Error completing SSE emitter", e);
        }
    }

    // Public methods for BetStreamService to use

    public String getLastTierMessage(String tier) {
        return "FREE".equals(tier) ? freeTierLastMessage : premiumTierLastMessage;
    }

    public void addUserToTier(String userId, String tier, SseEmitter emitter) {
        Map<String, SseEmitter> tierUsers = "FREE".equals(tier) ? freeUserConnections : premiumUserConnections;
        tierUsers.put(userId, emitter);
        log.info("Added user {} to {} tier (total: {} users)", userId, tier, tierUsers.size());
    }

    public void removeUserFromTier(String userId, String tier) {
        Map<String, SseEmitter> tierUsers = "FREE".equals(tier) ? freeUserConnections : premiumUserConnections;
        SseEmitter removed = tierUsers.remove(userId);
        if (removed != null) {
            completeEmitterSafely(removed);
            log.info("Removed user {} from {} tier (remaining: {} users)", userId, tier, tierUsers.size());
        }
    }

    public boolean isTierConnected(String tier) {
        return "FREE".equals(tier) ? freeTierConnected : premiumTierConnected;
    }

    public int getTierUserCount(String tier) {
        Map<String, SseEmitter> tierUsers = "FREE".equals(tier) ? freeUserConnections : premiumUserConnections;
        return tierUsers.size();
    }

    public int getTotalUserCount() {
        return freeUserConnections.size() + premiumUserConnections.size();
    }
}