package org.satochip.client.seedkeeper;

public enum SeedkeeperExportRights {
    EXPORT_FORBIDDEN((byte) 0x00),
    EXPORT_PLAINTEXT_ALLOWED((byte) 0x01),
    EXPORT_ENCRYPTED_ONLY((byte) 0x02),
    EXPORT_AUTHENTICATED_ONLY((byte) 0x03);

    private final byte value;

    SeedkeeperExportRights(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }

    public static SeedkeeperExportRights fromRawValue(byte rawValue) {
        for (SeedkeeperExportRights type : SeedkeeperExportRights.values()) {
            if (type.getValue() == rawValue) {
                return type;
            }
        }
        return SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED; // default
    }
}
