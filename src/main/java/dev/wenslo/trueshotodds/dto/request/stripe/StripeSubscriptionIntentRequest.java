package dev.wenslo.trueshotodds.dto.request.stripe;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class StripeSubscriptionIntentRequest {

    @NotBlank(message = "Plan is required")
    private String planId;

    @NotBlank(message = "billingCycle is required")
    private String billingCycle;

    private String email;

    private String fullName;
}