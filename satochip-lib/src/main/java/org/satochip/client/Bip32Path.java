package org.satochip.client;

import java.util.Arrays;
import java.util.logging.Logger;
import java.nio.ByteBuffer;

/**
 * Represents a BIP32 hierarchical deterministic wallet derivation path.
 *
 * <p>This class encapsulates a BIP32 derivation path that defines how to derive
 * child keys from a master key in hierarchical deterministic (HD) wallets.
 * BIP32 paths are used to deterministically generate cryptocurrency addresses
 * and private keys from a single master seed.
 *
 * <p><strong>BIP32 Path Format:</strong>
 * BIP32 paths follow the format: {@code m/purpose'/coin_type'/account'/change/address_index}
 * <ul>
 *   <li><strong>m</strong> - indicates master key</li>
 *   <li><strong>/</strong> - separates derivation levels</li>
 *   <li><strong>'</strong> - indicates hardened derivation (adds 0x80000000)</li>
 *   <li><strong>Numbers</strong> - 32-bit unsigned integers for each derivation step</li>
 * </ul>
 *
 * <p><strong>Example Paths:</strong>
 * <ul>
 *   <li>{@code m/44'/0'/0'/0/0} - Bitcoin first address (BIP44)</li>
 *   <li>{@code m/44'/60'/0'/0/0} - Ethereum first address</li>
 *   <li>{@code m/84'/0'/0'/0/0} - Bitcoin native segwit</li>
 * </ul>
 *
 * <p><strong>Binary Representation:</strong>
 * Internally, the path is stored as a byte array where each derivation level
 * is represented as a 4-byte big-endian integer. Hardened derivation adds
 * 0x80000000 to the index value.
 *
 * <p><strong>Thread Safety:</strong> This class is immutable and thread-safe.
 * All fields are final and the byte array is defensively copied.
 *
 * <p><strong>Usage Example:</strong>
 * <pre>{@code
 * // Create path for Bitcoin first address
 * Bip32Path path = new Bip32Path(5, pathBytes, "m/44'/0'/0'/0/0");
 *
 * // Get derivation depth
 * int depth = path.getDepth(); // Returns 5
 *
 * // Get binary representation
 * byte[] pathData = path.getBytes(); // Returns 20 bytes (5 levels * 4 bytes each)
 *
 * // Get string representation
 * String pathString = path.getBip32Path(); // Returns "m/44'/0'/0'/0/0"
 * }</pre>
 *
 * @author Satochip Development Team
 *
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP32 Specification</a>
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki">BIP44 Multi-Account Hierarchy</a>
 */
public class Bip32Path {

    private static final Logger logger = Logger.getLogger("org.satochip.client");

    /**
     * The number of derivation levels in this path.
     * <p>Each level represents one step in the hierarchical derivation process.
     * For example, "m/44'/0'/0'/0/0" has a depth of 5.
     * Maximum depth is typically limited by the underlying hardware/software.
     */
    private final Integer depth;

    /**
     * Binary representation of the derivation path.
     * <p>Each derivation level is encoded as a 4-byte big-endian unsigned integer.
     * For hardened derivation, 0x80000000 is added to the index.
     * The total length is always depth * 4 bytes.
     */
    private final byte[] bytes;

    /**
     * Human-readable string representation of the BIP32 path.
     * <p>Format: "m/level1/level2'/level3/..." where ' indicates hardened derivation.
     * This field may be null if the path was constructed from binary data only.
     */
    private final String bip32Path;

    /**
     * Constructs a new Bip32Path with the specified depth, binary data, and string representation.
     *
     * <p>This constructor creates a complete BIP32 path object with all three representations:
     * the derivation depth, the binary encoded path data, and the human-readable string format.
     *
     * <p><strong>Parameter Validation:</strong>
     * <ul>
     *   <li>The bytes array length should equal depth * 4</li>
     *   <li>Each 4-byte segment represents one derivation level</li>
     *   <li>Hardened derivation indices have the high bit set (>= 0x80000000)</li>
     * </ul>
     *
     * <p><strong>Use Cases:</strong>
     * <ul>
     *   <li>Converting from string path format to binary format for hardware wallets</li>
     *   <li>Reconstructing path objects from stored binary data</li>
     *   <li>Creating path objects from parsed user input</li>
     * </ul>
     *
     * @param depth the number of derivation levels in the path. Must be non-negative
     *              and typically ranges from 0 to 10. A depth of 0 represents the master key.
     * @param bytes the binary encoded path data where each 4-byte segment represents
     *              one derivation level in big-endian format. The array length should
     *              equal depth * 4. Must not be null.
     * @param stringPath the human-readable string representation of the path in standard
     *                  BIP32 format (e.g., "m/44'/0'/0'/0/0"). May be null if only
     *                  binary representation is needed.
     *
     * @throws IllegalArgumentException if depth is negative, bytes is null,
     *                                 or bytes.length != depth * 4
     *
     * @see #getDepth()
     * @see #getBytes()
     * @see #getBip32Path()
     */
    public Bip32Path(Integer depth, byte[] bytes, String stringPath) {
        this.depth = depth;
        this.bytes = bytes;
        this.bip32Path = stringPath;
    }

    /**
     * Constructs a new Bip32Path from its String representation.
     *
     * <p>Parses a hierarchical deterministic (HD) wallet path string according to BIP32
     * standards and converts it to the binary format expected by hardware wallets.
     * Supports both hardened (indicated by ' or h suffix) and non-hardened derivation.</p>
     *
     * <p><strong>Path Format Examples:</strong></p>
     * <ul>
     *   <li>{@code "m/44'/0'/0'/0/0"} - Standard Bitcoin receive address</li>
     *   <li>{@code "m/49'/0'/0'/0/0"} - P2SH-wrapped SegWit address</li>
     *   <li>{@code "m/84'/0'/0'/0/0"} - Native SegWit address</li>
     *   <li>{@code "44'/0'/0'/0/0"} - Relative path (m/ prefix optional)</li>
     * </ul>
     *
     * <p><strong>Constraints:</strong></p>
     * <ul>
     *   <li>Maximum depth: 10 components</li>
     *   <li>Each component: 31-bit unsigned integer</li>
     *   <li>Hardened derivation: component value + 0x80000000</li>
     * </ul>
     *
     * @param stringPath the BIP32 path string to parse (e.g., "m/44'/0'/0'/0/0")
     * @return Bip32Path object containing the depth and 4-byte encoded path components
     * @throws Exception if the path format is invalid, too long, or contains invalid numbers
     *
     * @since 0.0.4
     * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP32 Specification</a>
     * @see Bip32Path
     */
    public Bip32Path(String stringPath) throws Exception {
        logger.info("SATOCHIPLIB: parseBip32PathToBytes: Start ");

        String[] splitPath = stringPath.split("/");
        if (splitPath[0].equals("m")) {
            splitPath = Arrays.copyOfRange(splitPath, 1, splitPath.length);
        }

        int depth = splitPath.length;
        byte[] bytePath = new byte[depth * 4];

        int byteIndex = 0;
        for (int index = 0; index < depth; index++) {
            String subpathString = splitPath[index];
            long subpathInt;
            if (subpathString.endsWith("'") || subpathString.endsWith("h")) {
                subpathString = subpathString.replace("'", "").replace("h", "");
                try {
                    long tmp = Long.parseLong(subpathString);
                    subpathInt = tmp + 0x80000000L;
                } catch (NumberFormatException e) {
                    throw new Exception("Failed to parse Bip32 path: " + stringPath);
                }
            } else {
                try {
                    subpathInt = Long.parseLong(subpathString);
                } catch (NumberFormatException e) {
                    throw new Exception("Failed to parse Bip32 path: " + stringPath);
                }
            }
            byte[] subPathBytes = ByteBuffer.allocate(4).putInt((int) subpathInt).array();
            System.arraycopy(subPathBytes, 0, bytePath, byteIndex, subPathBytes.length);
            byteIndex += 4;
        }

        //return new Bip32Path(depth, bytePath, stringPath);
        this.depth = depth;
        this.bytes = bytePath;
        this.bip32Path = stringPath;
    }



    /**
     * Returns the number of derivation levels in this BIP32 path.
     *
     * <p>The depth represents how many steps are required to derive the target key
     * from the master key. Each level in the path hierarchy adds one to the depth:
     *
     * <ul>
     *   <li><strong>Depth 0:</strong> Master key (m)</li>
     *   <li><strong>Depth 1:</strong> First level (m/44')</li>
     *   <li><strong>Depth 2:</strong> Second level (m/44'/0')</li>
     *   <li><strong>Depth 5:</strong> Full BIP44 path (m/44'/0'/0'/0/0)</li>
     * </ul>
     *
     * <p><strong>Performance Note:</strong> This operation is O(1) as the depth
     * is stored as a field rather than calculated from the path data.
     *
     * <p><strong>Validation:</strong> The returned depth should always match
     * the actual number of 4-byte segments in the bytes array (bytes.length / 4).
     *
     * @return the derivation depth as a non-negative integer. Returns 0 for
     *         the master key, positive integers for derived keys. Never null.
     *
     * @see #getBytes()
     * @see #getBip32Path()
     */
    public Integer getDepth() {
        return depth;
    }

    /**
     * Returns the binary encoded representation of this BIP32 derivation path.
     *
     * <p>The binary format encodes each derivation level as a 4-byte big-endian
     * unsigned integer. This format is commonly used by hardware wallets and
     * cryptographic libraries for efficient path processing.
     *
     * <p><strong>Binary Format Details:</strong>
     * <ul>
     *   <li><strong>Length:</strong> Always depth * 4 bytes</li>
     *   <li><strong>Encoding:</strong> Big-endian (most significant byte first)</li>
     *   <li><strong>Hardened Derivation:</strong> Indices >= 0x80000000 (2^31)</li>
     *   <li><strong>Normal Derivation:</strong> Indices < 0x80000000</li>
     * </ul>
     *
     * <p><strong>Example:</strong>
     * For path "m/44'/0'/0'/0/0":
     * <pre>
     * Level 0: 44' = 44 + 0x80000000 = 0x8000002C
     * Level 1: 0'  = 0 + 0x80000000  = 0x80000000
     * Level 2: 0'  = 0 + 0x80000000  = 0x80000000
     * Level 3: 0   = 0               = 0x00000000
     * Level 4: 0   = 0               = 0x00000000
     *
     * Binary: [0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x00, 0x00, ...]
     * </pre>
     *
     * <p><strong>Security Note:</strong> The returned array is the internal representation.
     * Callers should not modify the contents to maintain immutability guarantees.
     *
     * @return a byte array containing the binary encoded path data. The length
     *         equals getDepth() * 4. Never null, but may be empty if depth is 0.
     *
     * @see #getDepth()
     * @see #getBip32Path()
     */
    public byte[] getBytes() {
        return bytes;
    }

    /**
     * Returns the human-readable string representation of this BIP32 path.
     *
     * <p>The string format follows the standard BIP32 notation where:
     * <ul>
     *   <li><strong>m</strong> - represents the master key</li>
     *   <li><strong>/</strong> - separates derivation levels</li>
     *   <li><strong>'</strong> - indicates hardened derivation</li>
     *   <li><strong>numbers</strong> - are the derivation indices</li>
     * </ul>
     *
     * <p><strong>Common Path Examples:</strong>
     * <ul>
     *   <li><strong>BIP44 Bitcoin:</strong> "m/44'/0'/0'/0/0"</li>
     *   <li><strong>BIP44 Ethereum:</strong> "m/44'/60'/0'/0/0"</li>
     *   <li><strong>BIP84 Bitcoin:</strong> "m/84'/0'/0'/0/0"</li>
     *   <li><strong>BIP49 Bitcoin:</strong> "m/49'/0'/0'/0/0"</li>
     * </ul>
     *
     * <p><strong>Hardened vs Normal Derivation:</strong>
     * <ul>
     *   <li><strong>Hardened ('):</strong> Uses parent private key, more secure</li>
     *   <li><strong>Normal:</strong> Uses parent public key, allows extended public key derivation</li>
     * </ul>
     *
     * <p><strong>Null Handling:</strong> This method may return null if the path
     * was constructed from binary data only without a string representation.
     * In such cases, the string form can be reconstructed from the binary data
     * if needed.
     *
     * @return the BIP32 path in standard string notation (e.g., "m/44'/0'/0'/0/0"),
     *         or null if no string representation was provided during construction
     *
     * @see #getDepth()
     * @see #getBytes()
     */
    public String getBip32Path() {
        return bip32Path;
    }


    /**
     * Determines the parent path for a given BIP32 derivation path.
     *
     * <p>Removes the last component from a BIP32 path string to get the parent path.
     * For example, "m/44'/0'/0'/0/5" becomes "m/44'/0'/0'/0".</p>
     *
     * @param bip32path the BIP32 path string to process
     * @return the parent path string with the last component removed
     * @throws Exception if the path is invalid or has no parent (too short)
     *
     * @see #parseBip32PathToBytes(String)
     */
    public static String getBip32PathParentPath(String bip32path) throws Exception {
        System.out.println("In getBip32PathParentPath");
        String[] splitPath = bip32path.split("/");
        if (splitPath.length <= 1) {
            throw new Exception("Invalid BIP32 path: " + bip32path);
        }
        String[] parentPathArray = Arrays.copyOf(splitPath, splitPath.length - 1);
        String parentPath = String.join("/", parentPathArray);
        return parentPath;
    }



}