package dev.wenslo.trueshotodds.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    private boolean success;
    private String message;
    private ProfileResponse user;

    public static AuthResponse success(String message, ProfileResponse user) {
        return new AuthResponse(true, message, user);
    }

    public static AuthResponse success(String message) {
        return new AuthResponse(true, message, null);
    }

    public static AuthResponse error(String message) {
        return new AuthResponse(false, message, null);
    }
}