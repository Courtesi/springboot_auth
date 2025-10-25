package dev.wenslo.trueshotodds.controller;

import dev.wenslo.trueshotodds.dto.response.FeaturePricingResponse;
import dev.wenslo.trueshotodds.service.FeatureService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/features")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Features", description = "Features pricing and traits")
public class FeatureController {

    private final FeatureService featureService;

    @GetMapping
    @Operation(summary = "Get list of features", description = "Returns detailed pricing tiers")
    public ResponseEntity<FeaturePricingResponse> getFeatures() {
        try {
            FeaturePricingResponse features = featureService.getFeaturePricings();

            return ResponseEntity.ok(features);
        } catch (Exception e) {
            log.error(e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(FeaturePricingResponse.error(e.getMessage()));
        }
    }
}
