package org.satochip.client.seedkeeper;

import org.satochip.io.APDUResponse;

public class SeedkeeperImportSecretResult {

    private final APDUResponse apduResponse;

    private final int sid;
    private final byte[] fingerprintFromSeedkeeper;

    public SeedkeeperImportSecretResult(APDUResponse apduResponse, int sid, byte[] fingerprintFromSeedkeeper) {
        this.apduResponse = apduResponse;
        this.sid = sid;
        this.fingerprintFromSeedkeeper = fingerprintFromSeedkeeper;
    }

    public APDUResponse getApduResponse() {
        return apduResponse;
    }

    public int getSid() {
        return sid;
    }
    public byte[] getFingerprintFromSeedkeeper() {
        return fingerprintFromSeedkeeper;
    }
}
