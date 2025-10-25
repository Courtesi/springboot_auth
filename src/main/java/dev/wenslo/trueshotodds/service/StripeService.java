package dev.wenslo.trueshotodds.service;

import com.stripe.Stripe;
import com.stripe.exception.InvalidRequestException;
import com.stripe.exception.SignatureVerificationException;
import com.stripe.exception.StripeException;
import com.stripe.model.*;
import com.stripe.model.checkout.Session;
import com.stripe.net.RequestOptions;
import com.stripe.net.Webhook;
import com.stripe.param.CustomerCreateParams;
import com.stripe.param.SubscriptionCreateParams;
import com.stripe.param.SubscriptionListParams;
import com.stripe.param.SubscriptionUpdateParams;
import com.stripe.param.checkout.SessionCreateParams;
import dev.wenslo.trueshotodds.dto.objects.FeatureObject;
import dev.wenslo.trueshotodds.dto.response.stripe.CancelSubscriptionResponse;
import dev.wenslo.trueshotodds.entity.SubscriptionPlan;
import dev.wenslo.trueshotodds.entity.SubscriptionStatus;
import dev.wenslo.trueshotodds.entity.User;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static io.netty.util.internal.StringUtil.length;

@Service
@Slf4j
public class StripeService {

    @Value("${app.stripe.secret-key}")
    private String stripeSecretKey;

    @Value("${app.stripe.publishable-key}")
    private String stripePublishableKey;

    @Value("${app.stripe.webhook-secret}")
    private String webhookSecret;

    @Value("${app.mail.base-url}")
    private String baseUrl;


    private final FeatureService featureService;
    private final UserService userService;

    public StripeService(FeatureService featureService, UserService userService) {
        this.featureService = featureService;
        this.userService = userService;
    }

    @PostConstruct
    public void init() {
        Stripe.apiKey = stripeSecretKey;
        log.info(webhookSecret);
//        log.info("Stripe API initialized with secret key: {}***", stripeSecretKey.substring(0, 7));
    }

    public Customer createCustomer(String email, String fullName, String userId) {
        try {
            CustomerCreateParams params = CustomerCreateParams.builder()
                    .setName(fullName)
                    .setEmail(email)
                    .putMetadata("userId", userId)
                    .build();
            return Customer.create(params);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String stripeConfig() {
        return stripePublishableKey;
    }

    public String createSubscriptionIntent(String planId, String billingCycle, String email, String fullName, String userId) {
        try {
            if (!billingCycle.equals("monthly") && !billingCycle.equals("yearly")) {
                throw new IllegalArgumentException("billingCycle must be monthly or yearly");
            }


            List<FeatureObject> features = featureService.getFeatures();
            Boolean sale = featureService.getSale();

            Optional<FeatureObject> matchingFeature = features.stream()
                    .filter(feature -> feature.getId().equals(planId))
                    .findFirst();

            if (matchingFeature.isPresent()) {
                FeatureObject feature = matchingFeature.get();

                //Price ID
                String priceId = billingCycle.equals("monthly")  ? feature.getMonthlyPriceId() : feature.getYearlyPriceId();

                if (priceId == null || priceId.isEmpty()) {
                    throw new RuntimeException("Feature price id is empty");
                }

                //Customer and customer ID
                Customer customer = createCustomer(email, fullName, userId);

                //Subscription Settings
                SubscriptionCreateParams.PaymentSettings paymentSettings =
                        SubscriptionCreateParams.PaymentSettings
                                .builder()
                                .setSaveDefaultPaymentMethod(SubscriptionCreateParams.PaymentSettings.SaveDefaultPaymentMethod.ON_SUBSCRIPTION)
                                .build();

                //Idempotency Key building
                RequestOptions options =
                        RequestOptions.builder()
                                .setIdempotencyKey(userId + "_" + priceId + "_" + System.currentTimeMillis())
                                .build();

                //Subscription params
                SubscriptionCreateParams params = SubscriptionCreateParams.builder()
                        .addItem(
                                SubscriptionCreateParams.Item.builder()
                                        .setPrice(priceId)
                                        .build()
                        )
                        .setCustomer(customer.getId()) //CUSTOMER ID UNIQUE HERE
                        .setPaymentSettings(paymentSettings)
                        .setPaymentBehavior(SubscriptionCreateParams.PaymentBehavior.DEFAULT_INCOMPLETE)
                        .addAllExpand(Arrays.asList("latest_invoice.confirmation_secret"))
                        .build();

                Subscription subscription = Subscription.create(params, options);

                String subscriptionId = subscription.getId();

                return subscription.getLatestInvoiceObject().getConfirmationSecret().getClientSecret();

            } else {
                // Handle not found case
                throw new IllegalArgumentException("Plan not found: " + planId);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public CancelSubscriptionResponse cancelSubscription(String userId, String reason) {
        try {
            // Find user by user ID and get their Stripe customer ID
            User user = userService.findUserById(userId);
            String stripeCustomerId = user.getStripeCustomerId();

            if (stripeCustomerId == null || stripeCustomerId.isEmpty()) {
                throw new IllegalArgumentException("User does not have an active Stripe customer account");
            }

            // Find active subscription for this customer
            SubscriptionCollection subscriptions = Subscription.list(
                    com.stripe.param.SubscriptionListParams.builder()
                            .setCustomer(stripeCustomerId)
                            .setStatus(SubscriptionListParams.Status.ACTIVE)
                            .setLimit(1L)
                            .build()
            );

            if (subscriptions.getData().isEmpty()) {
                throw new IllegalArgumentException("No active subscription found");
            }

            Subscription activeSubscription = subscriptions.getData().getFirst();
            String subscriptionId = activeSubscription.getId();

            // Cancel at period end (end-of-period approach)
            SubscriptionUpdateParams updateParams = SubscriptionUpdateParams.builder()
                    .setCancelAtPeriodEnd(true)
                    .putMetadata("cancellation_reason", reason != null ? reason : "User requested cancellation")
                    .build();

            Subscription canceledSubscription = activeSubscription.update(updateParams);

            // Calculate when access ends (current period end) for response only
            long currentPeriodEndTimestamp = canceledSubscription.getItems().getData().getFirst().getCurrentPeriodEnd();
            java.time.LocalDateTime periodEndDateTime = java.time.Instant.ofEpochSecond(currentPeriodEndTimestamp)
                    .atZone(java.time.ZoneId.systemDefault())
                    .toLocalDateTime();
            java.time.LocalDate accessEndsOn = periodEndDateTime.toLocalDate();

            // NOTE: Database will be updated via webhook when Stripe sends subscription.updated event
            // This ensures single source of truth and prevents race conditions

            log.info("Scheduled subscription cancellation for user ID: {} - Access ends on: {} (will be updated via webhook)", userId, accessEndsOn);

            return CancelSubscriptionResponse.success(
                    "Subscription will be canceled at the end of your current billing period",
                    accessEndsOn
            );

        } catch (Exception e) {
            log.error("Failed to cancel subscription for user ID: {}", userId, e);
            throw new RuntimeException("Failed to cancel subscription: " + e.getMessage(), e);
        }
    }

    public void processWebhook(String payload, String signatureHeader) throws StripeException {
        Event event = null;

        try {
            event = Webhook.constructEvent(payload, signatureHeader, webhookSecret);
        } catch (SignatureVerificationException e) {
            log.error("Invalid webhook signature", e);
            throw new IllegalArgumentException("Invalid webhook signature");
        }

        // Deserialize the nested object inside the event
        EventDataObjectDeserializer dataObjectDeserializer = event.getDataObjectDeserializer();
        StripeObject stripeObject = null;

        if (dataObjectDeserializer.getObject().isPresent()) {
            stripeObject = dataObjectDeserializer.getObject().get();
        } else {
            log.warn("Deserialization failed for event: {}", event.getId());
            throw new IllegalStateException("Failed to deserialize webhook event");
        }

        handleWebhookEvent(event, stripeObject);
    }

    private void handleWebhookEvent(Event event, StripeObject stripeObject) {
        log.info("Processing {} with ID: {}", event.getType(), event.getId());

        switch (event.getType()) {
            case "customer.created":
                handleCustomerCreated((Customer) stripeObject);
                break;

            case "customer.updated":
                handleCustomerUpdated((Customer) stripeObject);
                break;

            case "customer.deleted":
                handleCustomerDeleted((Customer) stripeObject);
                break;

            case "invoice.created":
                handleInvoiceCreated((Invoice) stripeObject);
                break;

            case "invoice.paid":
                handleInvoicePaid((Invoice) stripeObject);
                break;

            case "invoice.payment_failed":
                handleInvoicePaymentFailed((Invoice) stripeObject);
                break;

            case "invoice.updated":
                handleInvoiceUpdated((Invoice) stripeObject);
                break;

            case "invoice.voided":
                handleInvoiceVoided((Invoice) stripeObject);
                break;

            case "customer.subscription.created":
                handleSubscriptionCreated((Subscription) stripeObject);
                break;

            case "customer.subscription.updated":
                handleSubscriptionUpdated((Subscription) stripeObject);
                break;

            case "customer.subscription.deleted":
                handleSubscriptionDeleted((Subscription) stripeObject);
                break;

            case "customer.subscription.paused":
                handleSubscriptionPaused((Subscription) stripeObject);
                break;

            case "customer.subscription.resumed":
                handleSubscriptionResumed((Subscription) stripeObject);
                break;

            case "customer.subscription.trial_will_end":
                handleSubscriptionTrialWillEnd((Subscription) stripeObject);
                break;

            case "payment_intent.canceled":
                handlePaymentIntentCanceled((PaymentIntent) stripeObject);
                break;

            case "payment_method.attached":
                handlePaymentMethodAttached((PaymentMethod) stripeObject);
                break;

            case "setup_intent.succeeded":
                handleSetupIntentSucceeded((SetupIntent) stripeObject);
                break;

            default:
                log.info("Unhandled event type: {}", event.getType());
        }
    }

    private void handleCustomerCreated(Customer customer) {
        log.info("Customer created: {}", customer.getId());

        String customerId = customer.getId();
        String email = customer.getEmail();
        String name = customer.getName();

        // Get user ID from metadata
        String userIdStr = customer.getMetadata().get("userId");
        if (userIdStr != null) {
            try {
                userService.updateStripeCustomerId(userIdStr, customerId);
                log.info("Linked Stripe customer {} to user ID: {}", customerId, userIdStr);
            } catch (Exception e) {
                log.error("Failed to link Stripe customer {} to user ID: {}", customerId, userIdStr, e);
            }
        } else {
            log.warn("Customer created without userId metadata: {}", customerId);
        }

        log.info("Customer details - ID: {}, Email: {}, Name: {}", customerId, email, name);
    }

    private void handleCustomerUpdated(Customer customer) {
        log.info("Customer updated: {}", customer.getId());

        String customerId = customer.getId();
        String email = customer.getEmail();
        String name = customer.getName();

        // Update customer details in your database
//        updateCustomerRecord(customerId, email, name);
        log.info("Updated customer details - ID: {}, Email: {}, Name: {}", customerId, email, name);
    }

    private void handleCustomerDeleted(Customer customer) {
        log.info("Customer deleted: {}", customer.getId());

        String customerId = customer.getId();

        // Clean up customer data immediately
        // deleteCustomerData(customerId);
        // Cancel any active subscriptions
        // cancelCustomerSubscriptions(customerId);
    }

    private void handleInvoiceCreated(Invoice invoice) {
        log.info("Invoice created: {}", invoice.getId());

        String customerId = invoice.getCustomer();
        // String subscriptionId = invoice.getSubscription(); // TODO: Fix subscription access
        String status = invoice.getStatus();

        // Track invoice creation for subscription management
        // createInvoiceRecord(invoice.getId(), customerId, status);
    }

    private void handleInvoiceUpdated(Invoice invoice) {
        log.info("Invoice updated: {}", invoice.getId());

        String customerId = invoice.getCustomer();
        // String subscriptionId = invoice.getSubscription(); // TODO: Fix subscription access
        String status = invoice.getStatus();

        // Update subscription tier based on invoice changes
        // updateSubscriptionTier(customerId, status);
        // Handle compliance/cancellation tier downgrades
        // checkSubscriptionCompliance(customerId, invoice);
    }

    private void handleInvoiceVoided(Invoice invoice) {
        log.info("Invoice voided: {}", invoice.getId());

        String customerId = invoice.getCustomer();
        // String subscriptionId = invoice.getSubscription(); // TODO: Fix subscription access

        // Handle canceled/refunded payments
        // processInvoiceVoid(customerId);
        // May need to adjust subscription status
        // handleSubscriptionAfterVoid(customerId);
    }

    private void handlePaymentIntentCanceled(PaymentIntent paymentIntent) {
        log.info("Payment intent canceled: {}", paymentIntent.getId());

        String customerId = paymentIntent.getCustomer();

        // Track abandoned payments for analytics
        // trackAbandonedPayment(paymentIntent.getId(), customerId);
        // Optional: Send follow-up email for conversion recovery
        // schedulePaymentRecoveryEmail(customerId);
    }

    private void handleInvoicePaid(Invoice invoice) {
        log.info("Invoice paid: {}", invoice.getId());

        String customerId = invoice.getCustomer();

        try {
            // Get customer details to access metadata for fallback
            Customer customer = Customer.retrieve(customerId);
            String userIdFromMetadata = customer.getMetadata().get("userId");

            // Grant premium access when invoice is paid
            grantPremiumAccessWithFallback(customerId, userIdFromMetadata);
            log.info("Granted premium access for customer: {}", customerId);
        } catch (Exception e) {
            log.error("Failed to grant premium access for customer: {}", customerId, e);
        }
    }

    private void handleInvoicePaymentFailed(Invoice invoice) {
        log.warn("Invoice payment failed: {}", invoice.getId());

        String customerId = invoice.getCustomer();

        try {
            // Get customer details to access metadata for fallback
            Customer customer = Customer.retrieve(customerId);
            String userIdFromMetadata = customer.getMetadata().get("userId");

            // Set subscription to past_due (will figure out correct end date later)
            setSubscriptionPastDueWithFallback(customerId, userIdFromMetadata, null);
            log.info("Set subscription to past_due for customer: {}", customerId);
        } catch (Exception e) {
            log.error("Failed to handle payment failure for customer: {}", customerId, e);
        }
    }

    private void handleSubscriptionDeleted(Subscription subscription) {
        log.info("Subscription deleted: {}", subscription.getId());

        String customerId = subscription.getCustomer();

        try {
            // Get customer details to access metadata for fallback
            Customer customer = Customer.retrieve(customerId);
            String userIdFromMetadata = customer.getMetadata().get("userId");

            // Extract current period end for proper expiry date handling
            LocalDateTime currentPeriodEnd = null;
            if (subscription.getItems() != null && !subscription.getItems().getData().isEmpty()) {
                Long currentPeriodEndTimestamp = subscription.getItems().getData().getFirst().getCurrentPeriodEnd();
                if (currentPeriodEndTimestamp != null) {
                    currentPeriodEnd = Instant.ofEpochSecond(currentPeriodEndTimestamp)
                        .atZone(ZoneId.systemDefault())
                        .toLocalDateTime();
                }
            }

            // When subscription is deleted, revoke access but honor the paid period
            revokePremiumAccessWithFallback(customerId, userIdFromMetadata, currentPeriodEnd);
            log.info("Revoked premium access for customer: {} - access ends: {}", customerId, currentPeriodEnd);
        } catch (Exception e) {
            log.error("Failed to revoke access for customer: {}", customerId, e);
        }
    }

    private void handleSubscriptionCreated(Subscription subscription) {
        log.info("Subscription created: {}", subscription.getId());

        String customerId = subscription.getCustomer();
        String subscriptionId = subscription.getId();
        String status = subscription.getStatus();

        try {
            // Get customer details to access metadata for fallback
            Customer customer = Customer.retrieve(customerId);
            String userIdFromMetadata = customer.getMetadata().get("userId");

            // Only grant access if subscription is active (payment completed)
            if ("active".equals(status)) {
                grantPremiumAccessWithFallback(customerId, userIdFromMetadata);
                log.info("Granted premium access for new subscription: {} (customer: {})", subscriptionId, customerId);
            } else {
                // Subscription created but not yet paid (incomplete status)
                SubscriptionStatus subscriptionStatus = mapStripeStatusToEnum(status);
                updateSubscriptionStatusWithFallback(customerId, userIdFromMetadata, subscriptionStatus, SubscriptionPlan.FREE, null);
                log.info("Subscription created but not active yet: {} (status: {})", subscriptionId, status);
            }
        } catch (Exception e) {
            log.error("Failed to handle subscription creation for customer: {}", customerId, e);
        }
    }

    private void handleSubscriptionUpdated(Subscription subscription) {
        log.info("Subscription updated: {}", subscription.getId());

        String customerId = subscription.getCustomer();
        String subscriptionId = subscription.getId();
        String status = subscription.getStatus();

        try {
            // Get customer details to access metadata for fallback
            Customer customer = Customer.retrieve(customerId);
            String userIdFromMetadata = customer.getMetadata().get("userId");

            // Extract current period end for proper expiry date handling
            LocalDateTime currentPeriodEnd = null;
            if (subscription.getItems() != null && !subscription.getItems().getData().isEmpty()) {
                Long currentPeriodEndTimestamp = subscription.getItems().getData().getFirst().getCurrentPeriodEnd();
                if (currentPeriodEndTimestamp != null) {
                    currentPeriodEnd = Instant.ofEpochSecond(currentPeriodEndTimestamp)
                        .atZone(ZoneId.systemDefault())
                        .toLocalDateTime();
                }
            }

            if ("active".equals(status)) {
                // Subscription became active (payment completed or reactivated)
                grantPremiumAccessWithFallback(customerId, userIdFromMetadata);
                log.info("Subscription became active - granted premium access: {} (customer: {})", subscriptionId, customerId);
            } else if ("past_due".equals(status)) {
                // Payment failed but subscription still active for grace period
                setSubscriptionPastDueWithFallback(customerId, userIdFromMetadata, currentPeriodEnd);
                log.info("Subscription past due (customer: {}) - grace period ends: {}", customerId, currentPeriodEnd);
            } else if ("canceled".equals(status)) {
                // Subscription was canceled - use current period end so user keeps access until paid period expires
                revokePremiumAccessWithFallback(customerId, userIdFromMetadata, currentPeriodEnd);
                log.info("Subscription canceled (customer: {}) - access ends: {}", customerId, currentPeriodEnd);
            } else {
                // Other status changes
                SubscriptionStatus subscriptionStatus = mapStripeStatusToEnum(status);
                updateSubscriptionStatusWithFallback(customerId, userIdFromMetadata, subscriptionStatus, SubscriptionPlan.FREE, currentPeriodEnd);
                log.info("Subscription status updated: {} (customer: {}) - period ends: {}", status, customerId, currentPeriodEnd);
            }
        } catch (Exception e) {
            log.error("Failed to handle subscription update for customer: {}", customerId, e);
        }
    }

    private void handleSubscriptionPaused(Subscription subscription) {
        log.info("Subscription paused: {}", subscription.getId());
        // Handle subscription pause

        String customerId = subscription.getCustomer();
        String subscriptionId = subscription.getId();

        // Update subscription status in your database
        // pauseSubscriptionAccess(customerId, subscriptionId);
        // Temporarily revoke access to premium features
        // suspendSubscriptionFeatures(customerId);
    }

    private void handleSubscriptionResumed(Subscription subscription) {
        log.info("Subscription resumed: {}", subscription.getId());
        // Handle subscription resume

        String customerId = subscription.getCustomer();
        String subscriptionId = subscription.getId();

        // Update subscription status in your database
        // resumeSubscriptionAccess(customerId, subscriptionId);
        // Restore access to premium features
        // restoreSubscriptionFeatures(customerId, subscription);
    }

    private void handleSubscriptionTrialWillEnd(Subscription subscription) {
        log.info("Subscription trial will end: {}", subscription.getId());
        // Handle trial ending notification

        String customerId = subscription.getCustomer();
        long trialEnd = subscription.getTrialEnd();

        // Notify user that trial is ending
        // sendTrialEndingNotification(customerId, trialEnd);
        // Prompt user to add payment method if not already present
        // requestPaymentMethodUpdate(customerId);
    }

    private void handlePaymentMethodAttached(PaymentMethod paymentMethod) {
        log.info("Payment method attached: {}", paymentMethod.getId());
        // Handle new payment method attachment

        String customerId = paymentMethod.getCustomer();
        String paymentMethodId = paymentMethod.getId();

        // Update customer's payment method in your database
        // updateCustomerPaymentMethod(customerId, paymentMethodId);
        // If this is the first payment method, may want to retry failed payments
        // retryFailedPayments(customerId);
    }

    private void handleSetupIntentSucceeded(SetupIntent setupIntent) {
        log.info("Setup intent succeeded: {}", setupIntent.getId());
        // Handle successful payment method setup

        String customerId = setupIntent.getCustomer();
        String paymentMethodId = setupIntent.getPaymentMethod();

        // Payment method was successfully set up for future payments
        // confirmPaymentMethodSetup(customerId, paymentMethodId);
        // May want to automatically start subscription if it was pending
        // activatePendingSubscription(customerId);
    }

    private SubscriptionStatus mapStripeStatusToEnum(String stripeStatus) {
        return switch (stripeStatus.toLowerCase()) {
            case "active" -> SubscriptionStatus.ACTIVE;
            case "canceled", "cancelled" -> SubscriptionStatus.CANCELLED;
            case "past_due" -> SubscriptionStatus.PAST_DUE;
            case "suspended" -> SubscriptionStatus.SUSPENDED;
            default -> SubscriptionStatus.SUSPENDED; // Default for unknown statuses
        };
    }

    // Fallback helper methods to handle race conditions
    private void grantPremiumAccessWithFallback(String stripeCustomerId, String userIdFromMetadata) {
        try {
            userService.grantPremiumAccess(stripeCustomerId);
        } catch (Exception e) {
            if (userIdFromMetadata != null) {
                log.info("Fallback: granting premium access using user ID from metadata: {}", userIdFromMetadata);
                userService.grantPremiumAccessByUserId(userIdFromMetadata);
            } else {
                throw e;
            }
        }
    }

    private void updateSubscriptionStatusWithFallback(String stripeCustomerId, String userIdFromMetadata,
                                                     SubscriptionStatus status, SubscriptionPlan plan, LocalDateTime endDate) {
        try {
            userService.updateSubscriptionStatus(stripeCustomerId, status, plan, endDate);
        } catch (Exception e) {
            if (userIdFromMetadata != null) {
                log.info("Fallback: updating subscription status using user ID from metadata: {}", userIdFromMetadata);
                userService.updateSubscriptionStatusByUserId(userIdFromMetadata, status, plan, endDate);
            } else {
                throw e;
            }
        }
    }

    private void setSubscriptionPastDueWithFallback(String stripeCustomerId, String userIdFromMetadata, LocalDateTime currentPeriodEnd) {
        try {
            userService.setSubscriptionPastDue(stripeCustomerId, currentPeriodEnd);
        } catch (Exception e) {
            if (userIdFromMetadata != null) {
                log.info("Fallback: setting subscription past due using user ID from metadata: {}", userIdFromMetadata);
                userService.setSubscriptionPastDueByUserId(userIdFromMetadata, currentPeriodEnd);
            } else {
                throw e;
            }
        }
    }

    private void revokePremiumAccessWithFallback(String stripeCustomerId, String userIdFromMetadata, LocalDateTime endDate) {
        try {
            userService.revokePremiumAccess(stripeCustomerId, endDate);
        } catch (Exception e) {
            if (userIdFromMetadata != null) {
                log.info("Fallback: revoking premium access using user ID from metadata: {}", userIdFromMetadata);
                userService.revokePremiumAccessByUserId(userIdFromMetadata, endDate);
            } else {
                throw e;
            }
        }
    }

    public void deleteStripeCustomer(String stripeCustomerId) {
        try {
            if (stripeCustomerId == null || stripeCustomerId.isEmpty()) {
                log.info("No Stripe customer ID provided, skipping deletion");
                return;
            }

            // First, get the customer to check for active subscriptions
            Customer customer = Customer.retrieve(stripeCustomerId);

            // Cancel all active subscriptions first
            SubscriptionCollection subscriptions = Subscription.list(
                    SubscriptionListParams.builder()
                            .setCustomer(stripeCustomerId)
                            .setStatus(SubscriptionListParams.Status.ACTIVE)
                            .build()
            );

            for (Subscription subscription : subscriptions.getData()) {
                try {
                    subscription.cancel();
                    log.info("Canceled subscription {} for customer {}", subscription.getId(), stripeCustomerId);
                } catch (InvalidRequestException e) {
                    if ("resource_missing".equals(e.getCode())) {
                        log.info("Subscription {} already canceled/deleted for customer {}", subscription.getId(), stripeCustomerId);
                    } else {
                        throw e;
                    }
                }
            }

            // Delete the customer
            customer.delete();
            log.info("Successfully deleted Stripe customer: {}", stripeCustomerId);

        } catch (StripeException e) {
            log.error("Failed to delete Stripe customer: {}", stripeCustomerId, e);
            throw new RuntimeException("Failed to delete Stripe customer: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error deleting Stripe customer: {}", stripeCustomerId, e);
            throw new RuntimeException("Unexpected error deleting Stripe customer: " + e.getMessage(), e);
        }
    }

}
