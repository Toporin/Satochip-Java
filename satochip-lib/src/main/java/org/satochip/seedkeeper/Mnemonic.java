//package org.satochip.seedkeeper;
//
//import com.google.common.base.Stopwatch;
//
//import org.bitcoinj.core.Sha256Hash;
//import org.bitcoinj.crypto.MnemonicException;
//import org.bitcoinj.crypto.PBKDF2SHA512;
//
//import java.io.BufferedReader;
//import java.io.FileNotFoundException;
//import java.io.IOException;
//import java.io.InputStream;
//import java.io.InputStreamReader;
//import java.nio.charset.StandardCharsets;
//import java.security.MessageDigest;
//import java.security.NoSuchAlgorithmException;
//import java.util.ArrayList;
//import java.util.Collections;
//import java.util.Date;
//import java.util.List;
//import java.util.Objects;
//import java.util.logging.Logger;
//import java.util.stream.Collectors;
//
//public class MnemonicCode {
//    private static final Logger logger = Logger.getLogger("org.satochip.client");
//
//    private final List<String> wordList;
//
//    private static final String BIP39_ENGLISH_RESOURCE_NAME = "seedkeeper/data/english.txt";
//    private static final String BIP39_ENGLISH_SHA256 = "ad90bf3beb7b0eb7e5acd74727dc0da96e0a280a258354e7293fb7e211ac03db";
//
//    /** UNIX time for when the BIP39 standard was finalised. This can be used as a default seed birthday. */
//    public static final Date BIP39_STANDARDISATION_TIME = new Date(1369267200L * 1000);
//
//
//    private static final int PBKDF2_ROUNDS = 2048;
//
//    public static MnemonicCode INSTANCE;
//
//    static {
//        try {
//            INSTANCE = new MnemonicCode();
//        } catch (IOException | NoSuchAlgorithmException e) {
//            logger.warning("Failed to load word list" + e);
//        }
//    }
//
//    /** Initialise from the included word list. Won't work on Android. */
//    public MnemonicCode() throws IOException, NoSuchAlgorithmException {
//        this(openDefaultWords(), BIP39_ENGLISH_SHA256);
//    }
//
//    private static InputStream openDefaultWords() throws IOException {
//        InputStream stream = MnemonicCode.class.getResourceAsStream(BIP39_ENGLISH_RESOURCE_NAME);
//        if (stream == null)
//            throw new FileNotFoundException(BIP39_ENGLISH_RESOURCE_NAME);
//        return stream;
//    }
//
//    /**
//     * Creates an MnemonicCode object, initializing with words read from the supplied input stream.  If a wordListDigest
//     * is supplied the digest of the words will be checked.
//     * @param wordStream input stream of 2048 line-seperated words
//     * @param wordListDigest hex-encoded Sha256 digest to check against
//     * @throws IOException if there was a problem reading the steam
//     * @throws IllegalArgumentException if list size is not 2048 or digest mismatch
//     */
//    public MnemonicCode(InputStream wordStream, String wordListDigest) throws IOException, IllegalArgumentException, NoSuchAlgorithmException {
//        List<String> textList = new ArrayList<>();
//
////        private static final HexFormat hexFormat = new HexFormat();
//
//        MessageDigest messageDigest = MessageDigest.getInstance("SHA_256");
//        InputStreamReader inputStreamReader = new InputStreamReader(wordStream, StandardCharsets.UTF_8);
//
//        try (BufferedReader bufferedReader = new BufferedReader(inputStreamReader)) {
////            this.wordList = bufferedReader.lines()
////                    .peek(word -> messageDigest.update(word.getBytes()))
////                    .collect(StreamUtils.toUnmodifiableList());
//            String line;
//            while ((line = bufferedReader.readLine()) != null) {
//                textList.add(line);
//                messageDigest.update(line.getBytes());
//            }
//            this.wordList = Collections.unmodifiableList(textList); // Make the list unmodifiable
//        }
//
//        if (this.wordList.size() != 2048)
//            throw new IllegalArgumentException("input stream did not contain 2048 words");
//
//        // If a wordListDigest is supplied check to make sure it matches.
//        if (wordListDigest != null) {
//            byte[] digest = messageDigest.digest();
//            String hexdigest = formatHex(digest);
//            if (!hexdigest.equals(wordListDigest))
//                throw new IllegalArgumentException("wordlist digest mismatch");
//        }
//    }
//
//    public String formatHex(byte[] bytes) {
//        StringBuilder stringBuilder = new StringBuilder(bytes.length * 2);
//        for (byte aByte : bytes) {
//            stringBuilder.append(byteToHex(aByte));
//        }
//        return stringBuilder.toString();
//    }
//
//    private String byteToHex(byte num) {
//        char[] hexDigits = new char[2];
//        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
//        hexDigits[1] = Character.forDigit((num & 0xF), 16);
//        return new String(hexDigits);
//    }
//
//    private String spaceJoiner(String delimiter) {
//        return list -> list.stream()
//                .map(Object::toString)
//                .collect(Collectors.joining(delimiter));
//    }
//
//    /**
//     * Gets the word list this code uses.
//     * @return unmodifiable word list
//     */
//    public List<String> getWordList() {
//        return wordList;
//    }
//
//    /**
//     * Convert mnemonic word list to seed.
//     */
//    public static byte[] toSeed(List<String> words, String passphrase) {
//        Objects.requireNonNull(passphrase, "A null passphrase is not allowed.");
//
//        // To create binary seed from mnemonic, we use PBKDF2 function
//        // with mnemonic sentence (in UTF-8) used as a password and
//        // string "mnemonic" + passphrase (again in UTF-8) used as a
//        // salt. Iteration count is set to 2048 and HMAC-SHA512 is
//        // used as a pseudo-random function. Desired length of the
//        // derived key is 512 bits (= 64 bytes).
//        //
//        String pass = InternalUtils.SPACE_JOINER.join(words);
//        String salt = "mnemonic" + passphrase;
//
//        Stopwatch watch = Stopwatch.start();
//        byte[] seed = PBKDF2SHA512.derive(pass, salt, PBKDF2_ROUNDS, 64);
//        logger.info("PBKDF2 took {}" + watch);
//        return seed;
//    }
//
//    /**
//     * Convert mnemonic word list to original entropy value.
//     */
//    public byte[] toEntropy(List<String> words) throws MnemonicException.MnemonicLengthException, MnemonicException.MnemonicWordException, MnemonicException.MnemonicChecksumException {
//        if (words.size() % 3 > 0)
//            throw new MnemonicException.MnemonicLengthException("Word list size must be multiple of three words.");
//
//        if (words.size() == 0)
//            throw new MnemonicException.MnemonicLengthException("Word list is empty.");
//
//        // Look up all the words in the list and construct the
//        // concatenation of the original entropy and the checksum.
//        //
//        int concatLenBits = words.size() * 11;
//        boolean[] concatBits = new boolean[concatLenBits];
//        int wordindex = 0;
//        for (String word : words) {
//            // Find the words index in the wordlist.
//            int ndx = Collections.binarySearch(this.wordList, word);
//            if (ndx < 0)
//                throw new MnemonicException.MnemonicWordException(word);
//
//            // Set the next 11 bits to the value of the index.
//            for (int ii = 0; ii < 11; ++ii)
//                concatBits[(wordindex * 11) + ii] = (ndx & (1 << (10 - ii))) != 0;
//            ++wordindex;
//        }
//
//        int checksumLengthBits = concatLenBits / 33;
//        int entropyLengthBits = concatLenBits - checksumLengthBits;
//
//        // Extract original entropy as bytes.
//        byte[] entropy = new byte[entropyLengthBits / 8];
//        for (int ii = 0; ii < entropy.length; ++ii)
//            for (int jj = 0; jj < 8; ++jj)
//                if (concatBits[(ii * 8) + jj])
//                    entropy[ii] |= 1 << (7 - jj);
//
//        // Take the digest of the entropy.
//        byte[] hash = Sha256Hash.hash(entropy);
//        boolean[] hashBits = bytesToBits(hash);
//
//        // Check all the checksum bits.
//        for (int i = 0; i < checksumLengthBits; ++i)
//            if (concatBits[entropyLengthBits + i] != hashBits[i])
//                throw new MnemonicException.MnemonicChecksumException();
//
//        return entropy;
//    }
//
//    /**
//     * Convert entropy data to mnemonic word list.
//     * @param entropy entropy bits, length must be a multiple of 32 bits
//     */
//    public List<String> toMnemonic(byte[] entropy) {
//        checkArgument(entropy.length % 4 == 0, () ->
//                "entropy length not multiple of 32 bits");
//        checkArgument(entropy.length > 0, () ->
//                "entropy is empty");
//
//        // We take initial entropy of ENT bits and compute its
//        // checksum by taking first ENT / 32 bits of its SHA256 hash.
//
//        byte[] hash = Sha256Hash.hash(entropy);
//        boolean[] hashBits = bytesToBits(hash);
//
//        boolean[] entropyBits = bytesToBits(entropy);
//        int checksumLengthBits = entropyBits.length / 32;
//
//        // We append these bits to the end of the initial entropy.
//        boolean[] concatBits = new boolean[entropyBits.length + checksumLengthBits];
//        System.arraycopy(entropyBits, 0, concatBits, 0, entropyBits.length);
//        System.arraycopy(hashBits, 0, concatBits, entropyBits.length, checksumLengthBits);
//
//        // Next we take these concatenated bits and split them into
//        // groups of 11 bits. Each group encodes number from 0-2047
//        // which is a position in a wordlist.  We convert numbers into
//        // words and use joined words as mnemonic sentence.
//
//        ArrayList<String> words = new ArrayList<>();
//        int nwords = concatBits.length / 11;
//        for (int i = 0; i < nwords; ++i) {
//            int index = 0;
//            for (int j = 0; j < 11; ++j) {
//                index <<= 1;
//                if (concatBits[(i * 11) + j])
//                    index |= 0x1;
//            }
//            words.add(this.wordList.get(index));
//        }
//
//        return words;
//    }
//
//    /**
//     * Check to see if a mnemonic word list is valid.
//     */
//    public void check(List<String> words) throws MnemonicException {
//        toEntropy(words);
//    }
//
//    private static boolean[] bytesToBits(byte[] data) {
//        boolean[] bits = new boolean[data.length * 8];
//        for (int i = 0; i < data.length; ++i)
//            for (int j = 0; j < 8; ++j)
//                bits[(i * 8) + j] = (data[i] & (1 << (7 - j))) != 0;
//        return bits;
//    }
//}