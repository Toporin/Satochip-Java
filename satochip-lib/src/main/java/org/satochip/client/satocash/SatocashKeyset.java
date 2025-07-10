package org.satochip.client.satocash;

/**
 * SatocashKeyset.java
 * Satochip-Java
 *
 * Created by Satochip on 23/06/2025.
 */
public class SatocashKeyset {
    private final byte index;
    private final byte[] id;
    private final byte mintIndex;
    private final byte unit;

    public SatocashKeyset(byte index, byte[] id, byte mintIndex, byte unit) {
        this.index = index;
        this.id = id.clone(); // defensive copy
        this.mintIndex = mintIndex;
        this.unit = unit;
    }

    public SatocashKeyset(byte[] bytes) {
        this.index = bytes[0];
        this.id = new byte[8];
        System.arraycopy(bytes, 1, this.id, 0, 8);
        this.mintIndex = bytes[9];
        this.unit = bytes[10];
    }

    public byte getIndex() {
        return index;
    }

    public byte[] getId() {
        return id.clone(); // defensive copy
    }

    public byte getMintIndex() {
        return mintIndex;
    }

    public byte getUnit() {
        return unit;
    }

    public String getIdHex() {
        return bytesToHex(id);
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