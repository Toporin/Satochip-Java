package org.satochip.client;

public class Bip32PathToBytesObject {

    private final Integer depth;
    private final byte[] bytes;

    public Bip32PathToBytesObject(Integer depth, byte[] bytes) {
        this.depth = depth;
        this.bytes = bytes;
    }

    public Integer getDepth() {
        return depth;
    }

    public byte[] getBytes() {
        return bytes;
    }
}