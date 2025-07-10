package org.satochip.client.satocash;

/**
 * SatocashUnit.java
 * Satochip-Java
 *
 * Created by Satochip on 23/06/2025.
 */
public enum SatocashUnit {
    SAT((byte) 0x01),
    MSAT((byte) 0x02),
    USD((byte) 0x03),
    EUR((byte) 0x04);

    private final byte value;

    SatocashUnit(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }

    public static SatocashUnit fromValue(byte value) {
        for (SatocashUnit unit : values()) {
            if (unit.value == value) {
                return unit;
            }
        }
        throw new IllegalArgumentException("Unknown SatocashUnit value: " + value);
    }
}
