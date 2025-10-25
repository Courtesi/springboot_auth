package dev.wenslo.trueshotodds.dto.response.stripe;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class StripeCheckoutResponse {

    private boolean success;
    private String message;
    private String clientSecret;
    private String sessionId;

    public static StripeCheckoutResponse success(String message, String clientSecret, String sessionId) {
        return new StripeCheckoutResponse(true, message, clientSecret, sessionId);
    }

    public static StripeCheckoutResponse error(String error) {
        return new StripeCheckoutResponse(false, error, null, null);
    }
}
