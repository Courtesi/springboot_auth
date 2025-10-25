package dev.wenslo.trueshotodds.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@Slf4j
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Value("${app.mail.base-url}")
    private String baseUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "OAuth2 authentication failed";

        if (exception instanceof OAuth2AuthenticationException oauth2Exception) {
            errorMessage = oauth2Exception.getError().getDescription();
            log.error("OAuth2 authentication failed: {} - {}",
                oauth2Exception.getError().getErrorCode(), errorMessage);
        } else {
            log.error("OAuth2 authentication failed", exception);
        }

        // Encode the error message for URL
        String encodedError = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);
        String targetUrl = baseUrl + "/login?error=oauth2_failed&message=" + encodedError;

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}