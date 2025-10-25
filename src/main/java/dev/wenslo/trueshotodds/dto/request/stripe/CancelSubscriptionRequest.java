package dev.wenslo.trueshotodds.dto.request.stripe;

import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class CancelSubscriptionRequest {

    @Size(max = 500, message = "Cancellation reason cannot exceed 500 characters")
    private String reason;
}