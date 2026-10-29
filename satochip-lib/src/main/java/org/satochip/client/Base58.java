package org.satochip.client;

import java.util.Arrays;

/**
 * Base58 encoding, with the Bitcoin alphabet.
 */
public final class Base58 {

    private static final char[] ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();

    private Base58() {
    }

    /**
     * Encodes the input in Base58. Each leading zero byte is encoded as a leading '1'.
     *
     * @param input the bytes to encode
     * @return the Base58 string
     */
    public static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            zeros++;
        }
        // repeated division of the big-endian base-256 number by 58
        byte[] number = Arrays.copyOf(input, input.length);
        char[] encoded = new char[input.length * 2]; // upper bound on the output length
        int outputStart = encoded.length;
        for (int inputStart = zeros; inputStart < number.length; ) {
            int remainder = 0;
            for (int i = inputStart; i < number.length; i++) {
                int digit = (remainder << 8) | (number[i] & 0xFF);
                number[i] = (byte) (digit / 58);
                remainder = digit % 58;
            }
            encoded[--outputStart] = ALPHABET[remainder];
            while (inputStart < number.length && number[inputStart] == 0) {
                inputStart++;
            }
        }
        for (int i = 0; i < zeros; i++) {
            encoded[--outputStart] = ALPHABET[0];
        }
        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    /**
     * Encodes the input in Base58Check: the input followed by the first 4 bytes of its double
     * SHA-256, encoded in Base58.
     *
     * @param input the bytes to encode
     * @return the Base58Check string
     */
    public static String encodeChecked(byte[] input) {
        byte[] checksum = Sha256.hashTwice(input);
        byte[] checksummed = Arrays.copyOf(input, input.length + 4);
        System.arraycopy(checksum, 0, checksummed, input.length, 4);
        return encode(checksummed);
    }
}
