package org.satochip.client.seedkeeper;

import org.satochip.io.APDUResponse;

import java.util.ArrayList;
import java.util.List;

public class SeedkeeperMasterSeedResult {
    private final APDUResponse apduResponse;
    private final List<SeedkeeperSecretHeader> headers = new ArrayList<>();

    public SeedkeeperMasterSeedResult(APDUResponse apduResponse, List<SeedkeeperSecretHeader> header) {
        this.apduResponse = apduResponse;
        this.headers.addAll(header);
    }

    public APDUResponse getApduResponse() {
        return apduResponse;
    }

    public List<SeedkeeperSecretHeader> getHeaders() {
        return headers;
    }
}