package dev.wenslo.trueshotodds.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Filter to handle session serialization errors gracefully.
 * Prevents application crashes by catching Redis serialization issues
 * and clearing corrupted sessions automatically.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class SessionResilienceFilter implements Filter {

    private final SessionRepository<?> sessionRepository;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        try {
            // Proceed with the request
            chain.doFilter(request, response);

        } catch (SerializationException ex) {
            log.error("Session serialization error caught in filter - cleaning up session", ex);
            handleSessionError(httpRequest, httpResponse, ex);

        } catch (Exception ex) {
            // Check if the exception is related to session serialization
            if (isSessionRelatedError(ex)) {
                log.error("Session-related error caught in filter - cleaning up session", ex);
                handleSessionError(httpRequest, httpResponse, ex);
            } else {
                // Re-throw non-session related exceptions
                throw ex;
            }
        }
    }

    private void handleSessionError(HttpServletRequest request, HttpServletResponse response, Exception ex)
            throws IOException {

        try {
            // Clear the security context
            SecurityContextHolder.clearContext();

            // Invalidate the session
            var session = request.getSession(false);
            if (session != null) {
                String sessionId = session.getId();
                log.info("Invalidating corrupted session in filter: {}", sessionId);

                try {
                    session.invalidate();
                } catch (Exception e) {
                    log.warn("Failed to invalidate local session: {}", sessionId, e);
                }

                // Delete from Redis
                try {
                    sessionRepository.deleteById(sessionId);
                    log.info("Successfully deleted corrupted session from Redis: {}", sessionId);
                } catch (Exception e) {
                    log.warn("Failed to delete session from Redis: {}", sessionId, e);
                }
            }

            // Return 401 Unauthorized with a clear message
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write(
                "{\"success\": false, \"message\": \"Your session has expired due to a technical issue. Please log in again.\"}"
            );

        } catch (Exception cleanupEx) {
            log.error("Error during session cleanup in filter", cleanupEx);
            // Last resort - return 500 but don't crash the app
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write(
                "{\"success\": false, \"message\": \"A technical error occurred. Please try again.\"}"
            );
        }
    }

    private boolean isSessionRelatedError(Exception ex) {
        String message = ex.getMessage();
        if (message == null) {
            return false;
        }

        // Check for common session/serialization error patterns
        return message.contains("SerializationException") ||
               message.contains("allowlist") ||
               message.contains("CustomUserPrincipal") ||
               message.contains("SessionUser") ||
               message.contains("deserialization") ||
               message.contains("Redis") ||
               (ex instanceof ClassCastException && message.contains("UserPrincipal"));
    }
}