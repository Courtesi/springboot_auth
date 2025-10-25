package dev.wenslo.trueshotodds.dto.response;

import dev.wenslo.trueshotodds.dto.objects.FeatureObject;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class FeaturePricingResponse {
    Boolean success;
    String message;
    List<FeatureObject> features;
    Float discount;
    Boolean sale;
    String saleSlogan;
    String saleEndsAt;

    public static FeaturePricingResponse success(List<FeatureObject> features, Float discount, Boolean sale, String saleSlogan, String saleEndsAt) {
        return new FeaturePricingResponse(true, "Features' pricing sent", features, discount, sale, saleSlogan, saleEndsAt);
    }

    public static FeaturePricingResponse error(String error) {
        return new FeaturePricingResponse(false, error, null, null, false, "", "");
    }
}
