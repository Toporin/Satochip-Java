package org.satochip.client.seedkeeper;

public enum SeedkeeperSecretType {
    DEFAULT_TYPE((byte) 0x00),
    MASTERSEED((byte) 0x10),
    BIP39_MNEMONIC((byte) 0x30),
    ELECTRUM_MNEMONIC((byte) 0x40),
    SHAMIR_SECRET_SHARE((byte) 0x50),
    PRIVKEY((byte) 0x60),
    PUBKEY((byte) 0x70),
    PUBKEY_AUTHENTICATED((byte) 0x71),
    KEY((byte) 0x80),
    PASSWORD((byte) 0x90),
    MASTER_PASSWORD((byte) 0x91),
    CERTIFICATE((byte) 0xA0),
    SECRET_2FA((byte) 0xB0),
    DATA((byte) 0xC0),
    WALLET_DESCRIPTOR((byte) 0xC1);

    private final byte value;

    SeedkeeperSecretType(byte value) {
        this.value = value;
    }

    public byte getValue() {
        return value;
    }


    public static SeedkeeperSecretType fromRawValue(byte rawValue) {
        for (SeedkeeperSecretType type : SeedkeeperSecretType.values()) {
            if (type.getValue() == rawValue) {
                return type;
            }
        }
        return SeedkeeperSecretType.DEFAULT_TYPE; 
    }
}
