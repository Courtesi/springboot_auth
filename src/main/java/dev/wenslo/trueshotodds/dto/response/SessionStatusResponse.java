package dev.wenslo.trueshotodds.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SessionStatusResponse {

    private boolean authenticated;
    private String sessionId;
    private String userId;
    private String userEmail;
    private String expiresAt;

    public static SessionStatusResponse authenticated(String sessionId, String userId, String userEmail, String expiresAt) {
        return new SessionStatusResponse(true, sessionId, userId, userEmail, expiresAt);
    }

    public static SessionStatusResponse unauthenticated() {
        return new SessionStatusResponse(false, null, null, null, null);
    }
}