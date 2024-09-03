package org.satochip.client.seedkeeper;

public enum SeedkeeperSecretOrigin {
    PLAIN_IMPORT((byte) 0x01),
    ENCRYPTED_IMPORT((byte) 0x02),
    GENERATED_ON_CARD((byte) 0x03);

    private final byte value;

    SeedkeeperSecretOrigin(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }

    public static SeedkeeperSecretOrigin fromRawValue(byte rawValue) {
        for (SeedkeeperSecretOrigin type : SeedkeeperSecretOrigin.values()) {
            if (type.getValue() == rawValue) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown raw value: " + rawValue);
    }
}
