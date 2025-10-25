package dev.wenslo.trueshotodds.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RateLimitService {

    private final RedisTemplate<String, String> redisTemplate;

    @Value("${app.security.rate-limit.enabled:true}")
    private boolean rateLimitEnabled;

    @Value("${app.security.rate-limit.login.requests-per-minute:5}")
    private int loginRequestsPerMinute;

    @Value("${app.security.rate-limit.registration.requests-per-minute:3}")
    private int registrationRequestsPerMinute;

    @Value("${app.security.rate-limit.password-reset.requests-per-minute:2}")
    private int passwordResetRequestsPerMinute;

    @Value("${app.security.rate-limit.resend-verification.requests-per-minute:2}")
    private int resendVerificationRequestsPerMinute;

    public boolean isAllowed(String clientIp, RateLimitType type) {
        if (!rateLimitEnabled) {
            return true;
        }

        int maxRequests = getMaxRequestsForType(type);
        String key = generateKey(clientIp, type);

        try {
            String currentCountStr = redisTemplate.opsForValue().get(key);
            int currentCount = currentCountStr != null ? Integer.parseInt(currentCountStr) : 0;

            if (currentCount >= maxRequests) {
                log.warn("Rate limit exceeded for IP: {} on {}, current count: {}, max: {}",
                    clientIp, type, currentCount, maxRequests);
                return false;
            }

            // Increment the counter
            if (currentCount == 0) {
                // First request - set with expiration
                redisTemplate.opsForValue().set(key, "1", Duration.ofMinutes(1));
            } else {
                // Increment existing counter
                redisTemplate.opsForValue().increment(key);
            }

            log.debug("Rate limit check passed for IP: {} on {}, count: {}/{}",
                clientIp, type, currentCount + 1, maxRequests);
            return true;

        } catch (Exception e) {
            log.error("Rate limit check failed for IP: {} on {}", clientIp, type, e);
            // Fail open - allow request if Redis is down
            return true;
        }
    }

    public RateLimitInfo getRateLimitInfo(String clientIp, RateLimitType type) {
        if (!rateLimitEnabled) {
            return new RateLimitInfo(0, getMaxRequestsForType(type), 0);
        }

        String key = generateKey(clientIp, type);
        int maxRequests = getMaxRequestsForType(type);

        try {
            String currentCountStr = redisTemplate.opsForValue().get(key);
            int currentCount = currentCountStr != null ? Integer.parseInt(currentCountStr) : 0;

            Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
            int resetTimeSeconds = ttl != null && ttl > 0 ? ttl.intValue() : 0;

            return new RateLimitInfo(currentCount, maxRequests, resetTimeSeconds);
        } catch (Exception e) {
            log.error("Failed to get rate limit info for IP: {} on {}", clientIp, type, e);
            return new RateLimitInfo(0, maxRequests, 0);
        }
    }

    private String generateKey(String clientIp, RateLimitType type) {
        return "rate_limit:%s:%s".formatted(type.name().toLowerCase(), clientIp);
    }

    private int getMaxRequestsForType(RateLimitType type) {
        return switch (type) {
            case LOGIN -> loginRequestsPerMinute;
            case REGISTRATION -> registrationRequestsPerMinute;
            case PASSWORD_RESET -> passwordResetRequestsPerMinute;
            case RESEND_VERIFICATION -> resendVerificationRequestsPerMinute;
        };
    }

    public enum RateLimitType {
        LOGIN,
        REGISTRATION,
        PASSWORD_RESET,
        RESEND_VERIFICATION
    }

    public static class RateLimitInfo {
        private final int currentCount;
        private final int maxRequests;
        private final int resetTimeSeconds;

        public RateLimitInfo(int currentCount, int maxRequests, int resetTimeSeconds) {
            this.currentCount = currentCount;
            this.maxRequests = maxRequests;
            this.resetTimeSeconds = resetTimeSeconds;
        }

        public int getCurrentCount() {
            return currentCount;
        }

        public int getMaxRequests() {
            return maxRequests;
        }

        public int getResetTimeSeconds() {
            return resetTimeSeconds;
        }

        public int getRemainingRequests() {
            return Math.max(0, maxRequests - currentCount);
        }

        public boolean isLimitExceeded() {
            return currentCount >= maxRequests;
        }
    }
}