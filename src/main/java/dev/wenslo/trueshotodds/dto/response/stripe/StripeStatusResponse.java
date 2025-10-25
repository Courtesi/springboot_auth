package dev.wenslo.trueshotodds.dto.response.stripe;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class StripeStatusResponse {

    private boolean success;
    private String status;
    private String email;

    public static StripeStatusResponse success(String status, String email) {
        return new StripeStatusResponse(true, status, email);
    }

    public static StripeStatusResponse error(String error) {
        return new StripeStatusResponse(false, error, null);
    }
}
