package dev.wenslo.trueshotodds.dto.request.stripe;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class StripeCheckoutRequest {

    @NotBlank(message = "priceId is required")
    private String priceId;

    private String email;
}