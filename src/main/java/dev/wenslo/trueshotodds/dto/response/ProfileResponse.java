package dev.wenslo.trueshotodds.dto.response;

import lombok.Data;

@Data
public class ProfileResponse {

    private String email;
    private String fullName;
    private String createdAt;
    private String lastLoginAt;
    private String oauthProvider;
    private String profilePictureUrl;
    private Boolean isOAuth2User;
    private Boolean hasPassword;
    private SubscriptionResponse subscription;
    private PreferencesResponse preferences;

    @Data
    public static class SubscriptionResponse {
        private String plan;
        private String status;
        private String billingCycle;
        private String nextBillingDate;
        private Boolean cancelAtPeriodEnd;
        private String expiryDate;
    }

    @Data
    public static class PreferencesResponse {
        private Boolean notifications;
        private Boolean emailUpdates;
    }
}