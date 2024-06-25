package org.satochip.client;

import org.satochip.io.APDUResponse;

public class AuthentikeyObject {

    private final APDUResponse apduResponse;

    private final byte[] authentikeyBytes;
    private final String authentikeyHex;

    public AuthentikeyObject(APDUResponse apduResponse, String sid, byte[] fingerprintFromSeedkeeper) {
        this.apduResponse = apduResponse;
        this.authentikeyHex = sid;
        this.authentikeyBytes = fingerprintFromSeedkeeper;
    }

    public APDUResponse getApduResponse() {
        return apduResponse;
    }

    public String getAuthentikeyHex() {
        return authentikeyHex;
    }
    public byte[] getAuthentikeyBytes() {
        return authentikeyBytes;
    }
}