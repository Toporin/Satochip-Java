//package org.satochip.seedkeeper;
//
//import java.math.BigInteger;
//import java.util.Arrays;
//import org.bouncycastle.jcajce.provider.digest.SHA256;
//import java.nio.charset.StandardCharsets;
//
///**
// * provides us with Base58 encoding and decoding functionality.
// */
//public class Base58 {
//    private static final int CHECKSUM_LENGTH = 4;
//
//    private static final String alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
//    private static final BigInteger zero = BigInteger.ZERO;
//    private static final BigInteger radix = BigInteger.valueOf(alphabet.length());
//
//    public static String checkEncode(byte[] bytes) {
//        byte[] checksum = calculateChecksum(bytes);
//        byte[] checksummedBytes = new byte[bytes.length + checksum.length];
//        System.arraycopy(bytes, 0, checksummedBytes, 0, bytes.length);
//        System.arraycopy(checksum, 0, checksummedBytes, bytes.length, checksum.length);
//        return encode(checksummedBytes);
//    }
//
//    public static byte[] checkDecode(String input) {
//        byte[] decodedChecksummedBytes = decode(input);
//        if (decodedChecksummedBytes == null) {
//            return null;
//        }
//
//        byte[] decodedChecksum = Arrays.copyOfRange(decodedChecksummedBytes, decodedChecksummedBytes.length - CHECKSUM_LENGTH, decodedChecksummedBytes.length);
//        byte[] decodedBytes = Arrays.copyOf(decodedChecksummedBytes, decodedChecksummedBytes.length - CHECKSUM_LENGTH);
//        byte[] calculatedChecksum = calculateChecksum(decodedBytes);
//
//        if (!Arrays.equals(decodedChecksum, calculatedChecksum)) {
//            return null;
//        }
//        return decodedBytes;
//    }
//
//    // not optimized
//    public static String encode(byte[] bytes) {
//        BigInteger integerBytes = new BigInteger(1, bytes);
//        StringBuilder answer = new StringBuilder();
//
//        while (integerBytes.compareTo(zero) > 0) {
//            BigInteger[] quotientAndRemainder = integerBytes.divideAndRemainder(radix);
//            integerBytes = quotientAndRemainder[0];
//            int remainder = quotientAndRemainder[1].intValue();
//            answer.insert(0, alphabet.charAt(remainder));
//        }
//
//        for (byte b : bytes) {
//            if (b == 0) {
//                answer.insert(0, alphabet.charAt(0));
//            } else {
//                break;
//            }
//        }
//
//        return answer.toString();
//    }
//
//    public static byte[] decode(String input) {
//        BigInteger answer = zero;
//        BigInteger i = BigInteger.ONE;
//        byte[] byteString = input.getBytes(StandardCharsets.UTF_8);
//
//        for (int j = byteString.length - 1; j >= 0; j--) {
//            int alphabetIndex = alphabet.indexOf(byteString[j]);
//            if (alphabetIndex == -1) {
//                return null;
//            }
//            answer = answer.add(i.multiply(BigInteger.valueOf(alphabetIndex)));
//            i = i.multiply(radix);
//        }
//
//        byte[] bytes = answer.toByteArray();
//        if (bytes[0] == 0) {
//            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
//        }
//
//        int leadingZeros = 0;
//        for (byte b : byteString) {
//            if (b == alphabet.charAt(0)) {
//                leadingZeros++;
//            } else {
//                break;
//            }
//        }
//
//        byte[] decodedBytes = new byte[leadingZeros + bytes.length];
//        System.arraycopy(bytes, 0, decodedBytes, leadingZeros, bytes.length);
//
//        return decodedBytes;
//    }
//
//    private static byte[] calculateChecksum(byte[] input) {
//        SHA256.Digest sha256 = new SHA256.Digest();
//        byte[] hashedBytes = sha256.digest(input);
//        byte[] doubleHashedBytes = sha256.digest(hashedBytes);
//        return Arrays.copyOf(doubleHashedBytes, CHECKSUM_LENGTH);
//    }
//
////    public static void main(String[] args) {
////        // Example usage
////        String encoded = Base58.base58CheckEncode("Hello, World!".getBytes(StandardCharsets.UTF_8));
////        System.out.println("Encoded: " + encoded);
////
////        byte[] decoded = Base58.base58CheckDecode(encoded);
////        System.out.println("Decoded: " + new String(decoded, StandardCharsets.UTF_8));
////    }
//}