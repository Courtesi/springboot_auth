package dev.wenslo.trueshotodds.controller;

import dev.wenslo.trueshotodds.dto.request.stripe.CancelSubscriptionRequest;
import dev.wenslo.trueshotodds.dto.request.stripe.StripeSubscriptionIntentRequest;
import dev.wenslo.trueshotodds.dto.response.stripe.CancelSubscriptionResponse;
import dev.wenslo.trueshotodds.dto.response.stripe.StripeConfigResponse;
import dev.wenslo.trueshotodds.dto.response.stripe.StripeSubscriptionIntentResponse;
import dev.wenslo.trueshotodds.security.CustomUserPrincipal;
import dev.wenslo.trueshotodds.service.StripeService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/payments")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Payment", description = "Payment gateway for subscription model")
public class PaymentController {

    private final StripeService stripeService;

    @GetMapping("/stripe/config")
    public ResponseEntity<StripeConfigResponse> getStripeConfig() {
        String pubKey = stripeService.stripeConfig();
        return ResponseEntity.ok(new StripeConfigResponse(pubKey));
    }

    @PostMapping("/stripe/create-subscription-intent")
    public ResponseEntity<StripeSubscriptionIntentResponse> stripeSubscriptionIntent(@RequestBody StripeSubscriptionIntentRequest stripeSubscriptionIntentRequest,
                                                                                     Authentication authentication) {
        try {
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(StripeSubscriptionIntentResponse.error("Unauthorized"));
            }
            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();

            String userEmail = userPrincipal.getEmail();
            String fullName = userPrincipal.getFullName();
            String userId = userPrincipal.getUserId();

            String clientSecret = stripeService.createSubscriptionIntent(stripeSubscriptionIntentRequest.getPlanId(),
                    stripeSubscriptionIntentRequest.getBillingCycle(),
                    userEmail, fullName, userId);

            return ResponseEntity.ok(StripeSubscriptionIntentResponse.success("Stripe subscription intent created", clientSecret));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(StripeSubscriptionIntentResponse.error(e.getMessage()));
        }
    }

    @PostMapping("/stripe/webhook")
    public ResponseEntity<String> handleWebhook(
            @RequestBody String payload,
            @RequestHeader("Stripe-Signature") String signatureHeader) {

        try {
            stripeService.processWebhook(payload, signatureHeader);
            return ResponseEntity.ok("Webhook processed successfully");

        } catch (IllegalArgumentException e) {
            log.error("Invalid webhook signature: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Invalid signature");

        } catch (IllegalStateException e) {
            log.error("Webhook processing error: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Processing error");

        } catch (Exception e) {
            log.error("Unexpected error processing webhook", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Internal server error");
        }
    }

    @PostMapping("/stripe/cancel-subscription")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<CancelSubscriptionResponse> cancelSubscription(
            @RequestBody CancelSubscriptionRequest request,
            Authentication authentication) {

        try {
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(CancelSubscriptionResponse.error("Unauthorized"));
            }

            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
            String userId = userPrincipal.getUserId();

            CancelSubscriptionResponse response = stripeService.cancelSubscription(userId, request.getReason());
            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            log.error("Invalid cancellation request: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(CancelSubscriptionResponse.error(e.getMessage()));

        } catch (Exception e) {
            log.error("Unexpected error canceling subscription", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(CancelSubscriptionResponse.error("Failed to cancel subscription"));
        }
    }
}
