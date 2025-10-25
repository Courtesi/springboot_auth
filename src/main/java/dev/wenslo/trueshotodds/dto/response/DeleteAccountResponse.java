package dev.wenslo.trueshotodds.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DeleteAccountResponse {

    private String message;
    private boolean success;

    public static DeleteAccountResponse success(String message) {
        return new DeleteAccountResponse(message, true);
    }

    public static DeleteAccountResponse error(String message) {
        return new DeleteAccountResponse(message, false);
    }
}