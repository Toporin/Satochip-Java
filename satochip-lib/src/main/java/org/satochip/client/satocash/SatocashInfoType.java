package org.satochip.client.satocash;

/**
 * SatocashProof.java
 * Satochip-Java
 *
 * Created by Satochip on 23/06/2025.
 */
public enum SatocashInfoType {
    STATE((byte) 0x00),
    KEYSET_INDEX((byte) 0x01),
    AMOUNT_EXPONENT((byte) 0x02),
    MINT_INDEX((byte) 0x03),
    UNIT((byte) 0x04);

    private final byte value;

    SatocashInfoType(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }

    public static SatocashInfoType fromValue(byte value) {
        for (SatocashInfoType type : values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown SatocashInfoType value: " + value);
    }
}
