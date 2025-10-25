package dev.wenslo.trueshotodds.service;

import dev.wenslo.trueshotodds.dto.objects.FeatureObject;
import dev.wenslo.trueshotodds.dto.response.FeaturePricingResponse;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@Slf4j
public class FeatureService {
    @Getter
    List<FeatureObject> features = new ArrayList<>();
    Float discount = 0.0f;
    @Getter
    Boolean sale = false;
    String saleSlogan = "";
    String saleEndsAt = "";

    @PostConstruct
    public void init() {
        List<String> freeFeatures = new ArrayList<>();
        freeFeatures.add("+EV Bet Opportunities: 3 at a time");
        freeFeatures.add("Arbitrage Betting Opportunities: 1 at a time");
        freeFeatures.add("Basic Profit/Loss Tracking");

        List<String> freeLimitations = new ArrayList<>();
        freeLimitations.add("No Advanced Analytics Dashboard");
//        freeLimitations.add("No API Access");

        FeatureObject free = new FeatureObject("free", "Starter", 0, 0,
                "Just for getting started", false,
                freeFeatures, freeLimitations, "Start Free");

        free.setMonthlyPriceId("");
        free.setYearlyPriceId("");

        features.add(free);

        ArrayList<String> premiumFeatures = new ArrayList<>();
        premiumFeatures.add("+EV Bet Opportunities: Unlimited");
        premiumFeatures.add("Arbitrage Betting Opportunities: Unlimited");
        premiumFeatures.add("Advanced Profit/Loss Tracking");
        premiumFeatures.add("Advanced Analytics Dashboard");
//        premiumFeatures.add("API Access");

        ArrayList<String> premiumLimitations = new ArrayList<>();

        FeatureObject premium = new FeatureObject("premium", "Premium", 15, 130,
                "Unlimited access to maximizing profits", true,
                premiumFeatures, premiumLimitations, "Start Premium");

        premium.setMonthlyPriceId("price_1S8EOXEAD3FWc7voQbXHI1fP");
        premium.setYearlyPriceId("price_1S8fm5EAD3FWc7voxUSwSwWJ");

        if (sale) {
            discount = 1 - ((float) premium.getSaleYearlyPrice() / ((float) premium.getSaleMonthlyPrice() * 12));
        } else {
            discount = 1 - ((float) premium.getYearlyPrice() / ((float) premium.getMonthlyPrice() * 12));
        }

        features.add(premium);
    }

    public FeaturePricingResponse getFeaturePricings() {
        return FeaturePricingResponse.success(features, discount, sale, saleSlogan, saleEndsAt);
    }

}
