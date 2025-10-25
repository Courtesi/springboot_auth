package dev.wenslo.trueshotodds.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CheckPasswordStrengthRequest {

    @NotBlank(message = "Password is required")
    private String password;
}