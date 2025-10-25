package dev.wenslo.trueshotodds.dto.request;

import lombok.Data;

@Data
public class UpdatePreferencesRequest {

    private Boolean notifications;

    private Boolean emailUpdates;
}