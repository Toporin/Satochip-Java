package org.satochip.client.seedkeeper;

public class SeedkeeperSecretEncryptedParams {
    private Integer sidPubKey;
    private byte[] iv;
    private byte[] hmac;

    public SeedkeeperSecretEncryptedParams(Integer sidPubKey, byte[] iv, byte[] hmac) {
        this.sidPubKey = sidPubKey;
        this.iv = iv;
        this.hmac = hmac;
    }

    public SeedkeeperSecretEncryptedParams() {
        this.sidPubKey = 0;
        this.iv = new byte[0];
        this.hmac = new byte[0];
    }

    // Getters and Setters
    public int getSidPubkey() {
        return sidPubKey;
    }

    public void setSidPubkey(int sidPubkey) {
        this.sidPubKey = sidPubkey;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public byte[] getHmac() {
        return hmac;
    }

    public void setHmac(byte[] hmac) {
        this.hmac = hmac;
    }
}

