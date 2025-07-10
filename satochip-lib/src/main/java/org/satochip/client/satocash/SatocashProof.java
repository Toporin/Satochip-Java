package org.satochip.client.satocash;

public class SatocashProof {

    private int index = 0; // Using int instead of short for unsigned 16-bit
    private byte state = 0;
    private byte keysetIndex = 0;
    private byte amountExponent = 0;
    private int amount = 0;
    private byte[] secret;
    private byte[] unblindedKey;

    public SatocashProof(byte[] bytes) {
        // response format [proof_index(2b) | proof_state(1b) | keyset_index(1b) | amount_exponent(1b) | unblinded_key(33b) | secret(32b)]
        if (bytes.length < 70) {
            throw new IllegalArgumentException("Byte array must be at least 70 bytes long");
        }

        // Convert unsigned bytes to int for index calculation
        index = ((bytes[0] & 0xFF) << 8) + (bytes[1] & 0xFF);
        state = bytes[2]; // todo check
        keysetIndex = bytes[3];
        amountExponent = bytes[4]; // todo check and parse?

        if ((state == 0x00) || (amountExponent == (byte) 0xFF)) {
            amount = 0;
        } else if ((state == 0x02) || ((amountExponent & 0x80) == 0x80)) {
            // spent amount
            amount = -(int) Math.pow(2, amountExponent & 0xFF);
        } else {
            amount = (int) Math.pow(2, amountExponent & 0xFF);
        }

        unblindedKey = new byte[33];
        System.arraycopy(bytes, 5, unblindedKey, 0, 33);

        secret = new byte[32];
        System.arraycopy(bytes, 38, secret, 0, 32);
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public byte getState() {
        return state;
    }

    public void setState(byte state) {
        this.state = state;
    }

    public byte getKeysetIndex() {
        return keysetIndex;
    }

    public void setKeysetIndex(byte keysetIndex) {
        this.keysetIndex = keysetIndex;
    }

    public byte getAmountExponent() {
        return amountExponent;
    }

    public void setAmountExponent(byte amountExponent) {
        this.amountExponent = amountExponent;
    }

    public int getAmount() {
        return amount;
    }

    public void setAmount(int amount) {
        this.amount = amount;
    }

    public byte[] getSecret() {
        return secret.clone();
    }

    public void setSecret(byte[] secret) {
        this.secret = secret.clone();
    }

    public byte[] getUnblindedKey() {
        return unblindedKey.clone();
    }

    public void setUnblindedKey(byte[] unblindedKey) {
        this.unblindedKey = unblindedKey.clone();
    }

    @Override
    public String toString() {
        return "index: " + index + "\n" +
                "state: " + state + "\n" +
                "keysetIndex: " + keysetIndex + "\n" +
                "amountExponent: " + amountExponent + "\n" +
                "amount: " + amount + "\n" +
                "secret: " + bytesToHex(secret) + "\n" +
                "unblindedKey: " + bytesToHex(unblindedKey) + "\n";
    }

    // Helper method to convert bytes to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}