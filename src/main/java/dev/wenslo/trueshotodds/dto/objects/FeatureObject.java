package dev.wenslo.trueshotodds.dto.objects;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class FeatureObject {
    private String id;
    private String name;
    private Integer monthlyPrice;
    private Integer yearlyPrice;
    private Integer saleMonthlyPrice = 0;
    private Integer saleYearlyPrice = 0;
    private String description;
    private Boolean popular;
    private List<String> features;
    private List<String> limitations;
    private String buttonText;
    private String gradient = "";
    private String borderColor = "";
    private String textColor = "";
    private String monthlyPriceId;
    private String yearlyPriceId;

    public FeatureObject(String id, String name, Integer monthlyPrice, Integer yearlyPrice, String description, Boolean popular, List<String> features, List<String> limitations, String buttonText) {
        this.id = id;
        this.name = name;
        this.monthlyPrice = monthlyPrice;
        this.yearlyPrice = yearlyPrice;
        this.description = description;
        this.popular = popular;
        this.features = features;
        this.limitations = limitations;
        this.buttonText = buttonText;
    }
}
