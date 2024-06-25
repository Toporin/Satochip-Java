//package org.satochip.client.seedkeeper
//
//import org.bouncycastle.crypto.digests.RIPEMD160Digest;
//import org.bouncycastle.jcajce.provider.digest.SHA3;
//
//import java.nio.charset.StandardCharsets;
//import java.util.Arrays;
//
///**
// * Utilities for the crypto module (e.g. using Bouncy Castle)
// */
//public class CryptoUtils {
//
//    /**
//     * Calculate RIPEMD160(input).
//     * @param input bytes to hash
//     * @return RIPEMD160(input)
//     */
//    public static byte[] digestRipeMd160(byte[] input) {
//        RIPEMD160Digest digest = new RIPEMD160Digest();
//        digest.update(input, 0, input.length);
//        byte[] ripmemdHash = new byte[20];
//        digest.doFinal(ripmemdHash, 0);
//        return ripmemdHash;
//    }
//}