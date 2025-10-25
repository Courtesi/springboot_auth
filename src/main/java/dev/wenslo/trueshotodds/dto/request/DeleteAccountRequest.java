package dev.wenslo.trueshotodds.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class DeleteAccountRequest {

    private String currentPassword;
}