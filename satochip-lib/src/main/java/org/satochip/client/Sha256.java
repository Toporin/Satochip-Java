package org.satochip.client;

import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * SHA-256 helpers, computed with the BouncyCastle lightweight API (no JCA provider lookup).
 */
public final class Sha256 {

    private Sha256() {
    }

    /**
     * Computes the SHA-256 hash of the input.
     *
     * @param input the bytes to hash
     * @return the 32-byte hash
     */
    public static byte[] hash(byte[] input) {
        SHA256Digest digest = new SHA256Digest();
        digest.update(input, 0, input.length);
        byte[] out = new byte[digest.getDigestSize()];
        digest.doFinal(out, 0);
        return out;
    }

    /**
     * Computes SHA-256(SHA-256(input)), as used by Bitcoin checksums.
     *
     * @param input the bytes to hash
     * @return the 32-byte hash
     */
    public static byte[] hashTwice(byte[] input) {
        return hash(hash(input));
    }
}
