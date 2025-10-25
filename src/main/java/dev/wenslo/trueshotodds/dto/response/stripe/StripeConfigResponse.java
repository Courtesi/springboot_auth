package dev.wenslo.trueshotodds.dto.response.stripe;

import lombok.Data;

@Data
public class StripeConfigResponse {

    private String publishableKey;

    public StripeConfigResponse(String publishableKey) {
        this.publishableKey = publishableKey;
    }
}
