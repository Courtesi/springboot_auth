package dev.wenslo.trueshotodds.dto.request.stripe;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class StripeStatusRequest {

    @NotBlank(message = "sessionId is required")
    private String sessionId;
}