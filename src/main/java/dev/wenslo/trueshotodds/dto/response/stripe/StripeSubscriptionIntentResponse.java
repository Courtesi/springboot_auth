package dev.wenslo.trueshotodds.dto.response.stripe;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class StripeSubscriptionIntentResponse {

    private boolean success;
    private String message;
    private String clientSecret;

    public static StripeSubscriptionIntentResponse success(String message, String clientSecret) {
        return new StripeSubscriptionIntentResponse(true, message, clientSecret);
    }

    public static StripeSubscriptionIntentResponse error(String error) {
        return new StripeSubscriptionIntentResponse(false, error, null);
    }
}