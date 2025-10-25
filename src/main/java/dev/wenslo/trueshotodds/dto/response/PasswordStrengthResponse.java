package dev.wenslo.trueshotodds.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordStrengthResponse {
    private boolean valid;
    private int score;
    private String strengthLevel;
    private List<String> suggestions;

    public static PasswordStrengthResponse of(boolean valid, int score, String strengthLevel, List<String> suggestions) {
        return new PasswordStrengthResponse(valid, score, strengthLevel, suggestions);
    }
}