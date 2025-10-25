package dev.wenslo.trueshotodds.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ConfirmDeleteAccountRequest {

    @NotBlank(message = "Deletion token is required")
    private String token;
}