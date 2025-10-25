package dev.wenslo.trueshotodds.dto.response.stripe;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDate;

@Data
@AllArgsConstructor
public class CancelSubscriptionResponse {
    private boolean success;
    private String message;
    private LocalDate accessEndsOn;

    public static CancelSubscriptionResponse success(String message, LocalDate accessEndsOn) {
        return new CancelSubscriptionResponse(true, message, accessEndsOn);
    }

    public static CancelSubscriptionResponse error(String message) {
        return new CancelSubscriptionResponse(false, message, null);
    }
}