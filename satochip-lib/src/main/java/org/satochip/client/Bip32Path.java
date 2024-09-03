package org.satochip.client;

public class Bip32Path {

    private final Integer depth;
    private final byte[] bytes;
    private final String bip32Path;

    public Bip32Path(Integer depth, byte[] bytes, String bip32Path) {
        this.depth = depth;
        this.bytes = bytes;
        this.bip32Path = bip32Path;
    }

    public Integer getDepth() {
        return depth;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public String getBip32Path() {
        return bip32Path;
    }
}