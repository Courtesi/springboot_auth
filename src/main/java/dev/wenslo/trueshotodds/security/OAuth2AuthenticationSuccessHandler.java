package dev.wenslo.trueshotodds.security;

import dev.wenslo.trueshotodds.entity.User;
import dev.wenslo.trueshotodds.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserService userService;

    @Value("${app.mail.base-url}")
    private String baseUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        try {
            OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

            // Debug: Log all available attributes (remove after debugging)
            log.info("OAuth2 attributes received: {}", oauth2User.getAttributes());

            // Extract user information from Google
            String email = oauth2User.getAttribute("email");
            String name = oauth2User.getAttribute("name");
            String googleId = oauth2User.getAttribute("sub");
            String picture = oauth2User.getAttribute("picture");

            // Fallback for Google ID if 'sub' is not available
            if (googleId == null) {
                googleId = oauth2User.getAttribute("id");
                log.warn("Google ID 'sub' was null, trying 'id': {}", googleId);
            }

            // Validate required fields
            if (email == null || email.trim().isEmpty()) {
                throw new IllegalStateException("Email is required for OAuth2 authentication but was null or empty");
            }
            if (googleId == null || googleId.trim().isEmpty()) {
                log.error("Google ID is null. Available attributes: {}", oauth2User.getAttributes());
                throw new IllegalStateException("Google user ID is required but was not provided. Check OAuth2 scopes and configuration.");
            }

            log.info("OAuth2 login attempt for email: {} with Google ID: {}", email, googleId);

            // Find or create user
            User user = userService.findOrCreateOAuth2User(email, name, googleId, "google", picture);

            // Update last login time
            userService.updateLastLogin(user.getId());

            // Create a custom authentication with CustomUserPrincipal
            CustomUserPrincipal userPrincipal = CustomUserPrincipal.from(user);
            org.springframework.security.authentication.UsernamePasswordAuthenticationToken newAuth =
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                    userPrincipal, null, userPrincipal.getAuthorities());

            // Update security context
            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(newAuth);
            SecurityContextHolder.setContext(securityContext);

            // Save security context to session
            HttpSession session = request.getSession(true);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);

            log.info("User {} successfully authenticated via Google OAuth2", email);

            // Redirect to frontend dashboard
            String targetUrl = baseUrl;
            getRedirectStrategy().sendRedirect(request, response, targetUrl);

        } catch (Exception e) {
            log.error("OAuth2 authentication success handling failed", e);
            // Redirect to login with error
            String errorUrl = baseUrl + "/login?error=oauth2_error";
            getRedirectStrategy().sendRedirect(request, response, errorUrl);
        }
    }
}