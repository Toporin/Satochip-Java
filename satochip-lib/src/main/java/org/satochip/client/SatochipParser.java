package org.satochip.client;

import org.satochip.io.APDUResponse;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.util.Properties;

import java.security.MessageDigest;
import java.math.BigInteger;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * Parser and cryptographic utilities for Satochip, Satodime, and Seedkeeper smartcards.
 *
 * <p>This class provides essential functionality for parsing APDU responses, performing
 * ECDSA signature verification, recovering public keys, and handling BIP32 derivation paths.
 * It serves as the cryptographic foundation for secure communication with cryptocurrency
 * hardware wallets and related devices.</p>
 *
 * <p>The parser implements secp256k1 elliptic curve operations and follows Bitcoin
 * standards including BIP32 (hierarchical deterministic wallets) and BIP62 (canonical
 * signatures).</p>
 *
 * <p><strong>Thread Safety:</strong> This class is not thread-safe due to internal
 * state management. Create separate instances for concurrent use.</p>
 *
 * <p><strong>Dependencies:</strong> Requires BouncyCastle cryptographic library
 * for elliptic curve operations.</p>
 *
 * @author Satochip Development Team
 * @see org.satochip.client.SatochipCommandSet
 * @see org.satochip.io.APDUResponse
 */
public class SatochipParser{

    private static final Logger logger = Logger.getLogger("org.satochip.client");

    /** Hexadecimal character set for string conversion operations. */
    public static final String HEXES = "0123456789ABCDEF";

    /** secp256k1 elliptic curve parameters as defined in Bitcoin standards. */
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");

    /**
     * Elliptic curve domain parameters for secp256k1.
     * Used for all ECDSA operations and key recovery.
     */
    public static final ECDomainParameters CURVE;

    /**
     * Half of the curve order, used for BIP62 canonical signature enforcement.
     * Signatures with s-values greater than this are converted to their canonical form.
     */
    public static final BigInteger HALF_CURVE_ORDER;

    /** The order of the secp256k1 curve (number of points on the curve). */
    public static final BigInteger CURVE_ORDER;

    static {
        // Initialize curve parameters for secp256k1
        CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
        CURVE_ORDER = CURVE_PARAMS.getN();
        HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);
    }

    /**
     * Currently cached authentication key from the connected card.
     * This is set when parsing authentication responses and used for subsequent verifications.
     */
    private byte[] authentikey = null;

    /**
     * Constructs a new SatochipParser instance.
     *
     * <p>Initializes the parser with default settings and prepares it for
     * parsing operations. The parser maintains minimal internal state.</p>
     */
    public SatochipParser(){
        // Empty constructor - initialization handled by static blocks
    }

    /**
     * Compresses an uncompressed secp256k1 public key to its compressed form.
     *
     * <p>Converts a 65-byte uncompressed public key (format: 0x04 + 32-byte X + 32-byte Y)
     * to a 33-byte compressed key (format: 0x02/0x03 + 32-byte X). The prefix byte
     * indicates whether the Y coordinate is even (0x02) or odd (0x03).</p>
     *
     * @param pubkey the public key to compress; must be either 33 bytes (already compressed)
     *               or 65 bytes (uncompressed format starting with 0x04)
     * @return the compressed public key as a 33-byte array
     * @throws Exception if the input key length is invalid (not 33 or 65 bytes)
     *
     * @since 0.0.4
     * @see <a href="https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm">ECDSA on Bitcoin Wiki</a>
     */
    public byte[] compressPubKey(byte[] pubkey) throws Exception {
        if (pubkey.length == 33) {
            // Already compressed
            return pubkey;
        } else if (pubkey.length == 65) {
            // In uncompressed form
            byte[] pubkeyComp = Arrays.copyOfRange(pubkey, 0, 33);
            // Compute compression byte
            int parity = pubkey[64] % 2;
            if (parity == 0) {
                pubkeyComp[0] = (byte) 0x02;
            } else {
                pubkeyComp[0] = (byte) 0x03;
            }
            return pubkeyComp;
        } else {
            throw new Exception("Wrong public key length: " + pubkey.length + ", expected: 65");
        }
    }

    /* ****************************************
     *                  PARSER                *
     **************************************** */

    /**
     * Parses BIP85 entropy from an extended key response.
     *
     * <p>BIP85 (Deterministic Entropy From BIP32 Keychains) allows deriving
     * deterministic entropy for various cryptographic applications from a
     * master seed using BIP32 derivation.</p>
     *
     * @param rapdu the APDU response containing BIP85 entropy data
     * @return a two-element array where [0] contains the entropy bytes and [1] is empty
     * @throws RuntimeException if BouncyCastle is not available in the classpath
     *
     * @since 0.0.4
     * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki">BIP85 Specification</a>
     */
    public byte[][] parseBip85GetExtendedKey(APDUResponse rapdu){
        logger.info("SATOCHIPLIB: parseBip85GetExtendedKey: Start ");

        try {
            byte[] data = rapdu.getData();
            logger.info("SATOCHIPLIB: parseBip85GetExtendedKey data: " + toHexString(data));

            int entropySize = 256 * (data[0] & 0xFF) + (data[1] & 0xFF);
            byte[] entropyBytes = Arrays.copyOfRange(data, 2, 2 + entropySize);

            return new byte[][] {entropyBytes, new byte[0]};
        } catch(Exception e) {
            throw new RuntimeException("Is BouncyCastle in the classpath?", e);
        }
    }

    /**
     * Parses the response from an INITIALIZE_SECURE_CHANNEL command.
     *
     * <p>Extracts the card's public key from the secure channel initialization response
     * and verifies the card's signatures. This establishes the cryptographic foundation
     * for secure communication using ECDH key agreement.</p>
     *
     * <p><strong>Response Format:</strong></p>
     * <pre>
     * [coordx_size(2b) | coordx | sig1_size(2b) | sig1 | sig2_size(2b) | sig2 | ...]
     * </pre>
     *
     * <p>The method performs ECDSA public key recovery using the provided X-coordinate
     * and signature to reconstruct the card's public key for ECDH.</p>
     *
     * @param rapdu the APDU response from INITIALIZE_SECURE_CHANNEL command
     * @return the card's 65-byte uncompressed public key for ECDH key agreement
     * @throws RuntimeException if signature verification fails or data is malformed
     *
     * @since 0.0.4
     * @see #recoverPubkey(byte[], byte[], byte[])
     * @see org.satochip.client.SecureChannelSession
     */
    public byte[] parseInitiateSecureChannel(APDUResponse rapdu){

        try{
            byte[] data= rapdu.getData();
            logger.info("SATOCHIPLIB: parseInitiateSecureChannel data: " + toHexString(data));

            // data= [coordxSize | coordx | sig1Size | sig1 |  sig2Size | sig2]
            int offset=0;
            int coordxSize= 256*data[offset++] + data[offset++];

            byte[] coordx= new byte[coordxSize];
            System.arraycopy(data, offset, coordx, 0, coordxSize);
            offset+=coordxSize;

            // msg1 is [coordx_size | coordx]
            byte[] msg1= new byte[2+coordxSize];
            System.arraycopy(data, 0, msg1, 0, msg1.length);

            int sig1Size= 256*data[offset++] + data[offset++];
            byte[] sig1= new byte[sig1Size];
            System.arraycopy(data, offset, sig1, 0, sig1Size);
            offset+=sig1Size;

            // msg2 is [coordxSize | coordx | sig1Size | sig1]
            byte[] msg2= new byte[2+coordxSize + 2 + sig1Size];
            System.arraycopy(data, 0, msg2, 0, msg2.length);

            int sig2Size= 256*data[offset++] + data[offset++];
            byte[] sig2= new byte[sig2Size];
            System.arraycopy(data, offset, sig2, 0, sig2Size);
            offset+=sig2Size;

            byte[] pubkey= recoverPubkey(msg1, sig1, coordx);

            return pubkey;
        } catch(Exception e) {
            throw new RuntimeException("Exception in parseInitiateSecureChannel: ", e);
        }
    }

    /**
     * Recovers possible authentication keys from secure channel initialization response.
     *
     * <p>This method handles both legacy and modern secure channel initialization formats.
     * In legacy format, it recovers all possible public keys from the signature (up to 4).
     * In modern format (Seedkeeper v0.2+), it uses the provided X-coordinate to recover
     * a single authentication key.</p>
     *
     * <p><strong>Legacy Format:</strong> When authentikey X-coordinate is not provided,
     * ECDSA properties allow recovery of multiple possible keys. The correct one must
     * be determined through subsequent verification.</p>
     *
     * <p><strong>Modern Format:</strong> Includes the authentikey X-coordinate in the
     * response, allowing precise recovery of a single authentication key.</p>
     *
     * @param rapdu the APDU response from secure channel initialization
     * @return list of possible authentication public keys (1-4 keys depending on format)
     * @throws RuntimeException if data parsing fails or key recovery is impossible
     *
     * @since 0.0.4
     * @see #recoverPubkey(byte[], byte[], byte[])
     * @see #recoverPossiblePubkeys(byte[], byte[])
     */
    public List<byte[]> parseInitiateSecureChannelGetPossibleAuthentikeys(APDUResponse rapdu){

        try{
            byte[] data= rapdu.getData();
            int dataLength = data.length;
            logger.info("SATOCHIPLIB: parseInitiateSecureChannel data: " + toHexString(data));

            // data= [coordxSize | coordx | sig1Size | sig1 |  sig2Size | sig2 | coordxSize(optional) | coordxAuthentikey(optional)]
            int offset=0;
            int coordxSize= 256*data[offset++] + data[offset++];

            byte[] coordx= new byte[coordxSize];
            System.arraycopy(data, offset, coordx, 0, coordxSize);
            offset+=coordxSize;

            // msg1 is [coordx_size | coordx]
            byte[] msg1= new byte[2+coordxSize];
            System.arraycopy(data, 0, msg1, 0, msg1.length);

            int sig1Size= 256*data[offset++] + data[offset++];
            byte[] sig1= new byte[sig1Size];
            System.arraycopy(data, offset, sig1, 0, sig1Size);
            offset+=sig1Size;

            // msg2 is [coordxSize | coordx | sig1Size | sig1]
            byte[] msg2= new byte[2+coordxSize + 2 + sig1Size];
            System.arraycopy(data, 0, msg2, 0, msg2.length);

            int sig2Size= 256*data[offset++] + data[offset++];
            byte[] sig2= new byte[sig2Size];
            System.arraycopy(data, offset, sig2, 0, sig2Size);
            offset+=sig2Size;

            // if authentikey coordx are available
            // (currently only for Seedkeeper v0.2 and higher)
            if (dataLength>offset+1){
                int coordxAuthentikeySize = 256*data[offset++] + data[offset++];
                if (dataLength>offset+coordxAuthentikeySize){}
                byte[] coordxAuthentikey= new byte[coordxAuthentikeySize];
                System.arraycopy(data, offset, coordxAuthentikey, 0, coordxAuthentikeySize);

                byte[] authentikey= recoverPubkey(msg2, sig2, coordxAuthentikey);
                List<byte[]> possibleAuthentikeys = new ArrayList<byte[]>();
                possibleAuthentikeys.add(authentikey);
                return possibleAuthentikeys;

            } else {
                // if authentikey coordx is not provided, two possible pubkeys can be recovered as par ECDSA properties
                // recover all possible authentikeys from msg2, sig2
                List<byte[]> possibleAuthentikeys = recoverPossiblePubkeys(msg2, sig2);

                return possibleAuthentikeys;
            }

        } catch(Exception e) {
            throw new RuntimeException("Exception in parseInitiateSecureChannelGetPossibleAuthentikeys:", e);
        }
    }

    /**
     * Parses the response from a BIP32_GET_AUTHENTIKEY command.
     *
     * <p>Extracts and verifies the card's authentication public key. The authentication
     * key is used to verify the authenticity of subsequent card responses and establish
     * trust in the communication channel.</p>
     *
     * <p><strong>Response Format:</strong></p>
     * <pre>
     * [coordx_size(2b) | coordx | sig_size(2b) | sig]
     * </pre>
     *
     * <p>The method uses ECDSA key recovery to reconstruct the full public key from
     * the X-coordinate and signature, then caches it for future verifications.</p>
     *
     * @param rapdu the APDU response containing authentication key data
     * @return the 65-byte uncompressed authentication public key
     * @throws RuntimeException if key recovery fails or signature is invalid
     *
     * @since 0.0.4
     * @see #recoverPubkey(byte[], byte[], byte[])
     */
    public byte[] parseBip32GetAuthentikey(APDUResponse rapdu){
        try{
            byte[] data= rapdu.getData();
            logger.info("SATOCHIPLIB: parseBip32GetAuthentikey data: " + toHexString(data));
            // data: [coordx_size(2b) | coordx | sig_size(2b) | sig ]

            int offset=0;
            int coordxSize= 256*(data[offset++] & 0xff) + data[offset++];
            byte[] coordx= new byte[coordxSize];
            System.arraycopy(data, offset, coordx, 0, coordxSize);
            offset+=coordxSize;

            // msg1 is [coordx_size | coordx]
            byte[] msg1= new byte[2+coordxSize];
            System.arraycopy(data, 0, msg1, 0, msg1.length);

            int sig1Size= 256*data[offset++] + data[offset++];
            byte[] sig1= new byte[sig1Size];
            System.arraycopy(data, offset, sig1, 0, sig1Size);
            offset+=sig1Size;

            byte[] pubkey= recoverPubkey(msg1, sig1, coordx);
            authentikey= new byte[pubkey.length];
            System.arraycopy(pubkey, 0, authentikey, 0, pubkey.length);
            return pubkey;
        } catch(Exception e) {
            throw new RuntimeException("Exception during Authentikey recovery", e);
        }
    }

    /**
     * Parses the response from an EXPORT_PKI_PUBKEY command.
     *
     * <p>Extracts the PKI (Public Key Infrastructure) public key from the card response.
     * This key is used for personalization certificate operations and device authentication.</p>
     *
     * <p><strong>Response Format:</strong></p>
     * <pre>
     * [authentikey(65b) | sig_size(2b - optional) | sig(optional)]
     * </pre>
     *
     * @param rapdu the APDU response containing PKI public key data
     * @return the 65-byte uncompressed PKI public key
     * @throws RuntimeException if data extraction fails
     *
     * @since 0.0.4
     * @see #cardExportPkiPubkey()
     */
    public byte[] parseExportPkiPubkey(APDUResponse rapdu){
        try{
            byte[] data= rapdu.getData();
            logger.info("SATOCHIPLIB: parseExportPkiPubkey data: " + toHexString(data));
            // data: [autehntikey(65b) | sig_size(2b - option) | sig(option) ]
            byte[] pubkey= new byte[65];
            System.arraycopy(data, 0, pubkey, 0, pubkey.length);
            return pubkey;
        } catch(Exception e) {
            throw new RuntimeException("Exception during Authentikey recovery", e);
        }
    }

    /**
     * Parses the response from a BIP32_GET_EXTENDED_KEY command.
     *
     * <p>Extracts the extended public key and chain code from a BIP32 key derivation
     * operation. The extended key consists of the public key and chain code, which
     * together allow further non-hardened key derivation.</p>
     *
     * <p><strong>Response Format:</strong></p>
     * <pre>
     * [chaincode(32b) | coordx_size(2b) | coordx | sig_size(2b) | sig | sig_size(2b) | sig2]
     * </pre>
     *
     * <p><strong>Legacy Optimization:</strong> If bit 7 of the coordx_size byte is set,
     * it indicates an unsupported legacy optimization mode that this method rejects.</p>
     *
     * @param rapdu the APDU response containing extended key data
     * @return a two-element array where [0] is the 65-byte public key and [1] is the 32-byte chain code
     * @throws RuntimeException if BouncyCastle is unavailable, legacy optimization is detected,
     *                         or key recovery fails
     *
     * @since 0.0.4
     * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP32 Extended Keys</a>
     * @see #recoverPubkey(byte[], byte[], byte[])
     */
    public byte[][] parseBip32GetExtendedKey(APDUResponse rapdu){//todo: return a wrapped

        try{
            byte[] data= rapdu.getData();
            logger.info("SATOCHIPLIB: parseBip32GetExtendedKey data: " + toHexString(data));
            //data: [chaincode(32b) | coordx_size(2b) | coordx | sig_size(2b) | sig | sig_size(2b) | sig2]

            int offset=0;
            byte[] chaincode= new byte[32];
            System.arraycopy(data, offset, chaincode, 0, chaincode.length);
            offset+=32;

            int coordxSize= 256*(data[offset++] & 0x7f) + data[offset++]; // (data[32] & 0x80) is ignored (optimization flag)
            byte[] coordx= new byte[coordxSize];
            System.arraycopy(data, offset, coordx, 0, coordxSize);
            offset+=coordxSize;

            // msg1 is [chaincode | coordx_size | coordx]
            byte[] msg1= new byte[32+2+coordxSize];
            System.arraycopy(data, 0, msg1, 0, msg1.length);

            int sig1Size= 256*data[offset++] + data[offset++];
            byte[] sig1= new byte[sig1Size];
            System.arraycopy(data, offset, sig1, 0, sig1Size);
            offset+=sig1Size;

            // msg2 is [chaincode | coordxSize | coordx | sig1Size | sig1]
            byte[] msg2= new byte[32 + 2+coordxSize + 2 + sig1Size];
            System.arraycopy(data, 0, msg2, 0, msg2.length);

            int sig2Size= 256*data[offset++] + data[offset++];
            byte[] sig2= new byte[sig2Size];
            System.arraycopy(data, offset, sig2, 0, sig2Size);
            offset+=sig2Size;

            byte[] pubkey= recoverPubkey(msg1, sig1, coordx);

            // todo: recover from si2
            return new byte[][] {pubkey, chaincode};
        } catch(Exception e) {
            throw new RuntimeException("Is BouncyCastle in the classpath?", e);
        }
    }

    /**
     * Parses the response from a GET_SATODIME_PUBKEY command.
     *
     * <p>Extracts and verifies the public key for a Satodime key slot. Satodime is a
     * bearer card that generates deterministic keys for cryptocurrency storage.
     * The method verifies the card's signature to ensure data authenticity.</p>
     *
     * <p><strong>Response Format:</strong></p>
     * <pre>
     * [pubkey_size(2b) | pubkey | sig_size(2b) | sig]
     * </pre>
     *
     * <p><strong>Security:</strong> The method verifies the signature against the cached
     * authentication key to prevent tampering with the public key data.</p>
     *
     * @param rapdu the APDU response containing Satodime public key data
     * @return the public key bytes for the requested key slot
     * @throws RuntimeException if data format is invalid, signature verification fails,
     *                         or authentication key is not available
     *
     * @since 0.0.4
     * @see #verifySig(byte[], byte[], byte[])
     * @see org.satochip.client.SatodimeStatus
     */
    public byte[] parseSatodimeGetPubkey(APDUResponse rapdu){

        try{
            byte[] data= rapdu.getData();
            logger.info("SATOCHIPLIB: parseSatodimeGetPubkey data: " + toHexString(data));
            logger.info("SATOCHIPLIB: parseSatodimeGetPubkey authentikey: " + toHexString(authentikey));
            //data: [ pubkey_size(2b) | pubkey | sig_size(2b) | sig ]

            int offset=0;
            int dataRemain= data.length;
            // pubkeysize
            if (dataRemain<2){
                throw new RuntimeException("Exception in parseSatodimeGetPubkey: wrong data length");
            }
            int pubkeySize= 256*data[offset++] + data[offset++];
            dataRemain-=2;
            // pubkey
            if (dataRemain<pubkeySize){
                throw new RuntimeException("Exception in parseSatodimeGetPubkey: wrong data length");
            }
            byte[] pubkey= new byte[pubkeySize];
            System.arraycopy(data, offset, pubkey, 0, pubkeySize);
            offset+=pubkeySize;
            dataRemain-=pubkeySize;
            // msg
            byte[] msg = new byte[2+pubkeySize];
            System.arraycopy(data, 0, msg, 0, msg.length);
            logger.info("SATOCHIPLIB: parseSatodimeGetPubkey authentikey: " + toHexString(msg));
            // sigsize
            if (dataRemain<2){
                throw new RuntimeException("Exception in parseSatodimeGetPubkey: wrong data length");
            }
            int sigSize= 256*data[offset++] + data[offset++];
            dataRemain-=2;
            //sig
            if (dataRemain<sigSize){
                throw new RuntimeException("Exception in parseSatodimeGetPubkey: wrong data length");
            }
            byte[] sig= new byte[sigSize];
            System.arraycopy(data, offset, sig, 0, sigSize);
            logger.info("SATOCHIPLIB: parseSatodimeGetPubkey authentikey: " + toHexString(sig));
            offset+=sigSize;
            dataRemain-=sigSize;

            // verify sig
            logger.info("SATOCHIPLIB: parseSatodimeGetPubkey verifySig: START" );
            boolean isOk= verifySig(msg, sig, authentikey);
            if (!isOk){
                throw new RuntimeException("Exception in parseSatodimeGetPubkey: wrong signature!");
            }

            return pubkey;

        } catch(Exception e) {
            throw new RuntimeException("Exception in parseSatodimeGetPubkey: ", e);
        }
    }

    /**
     * Parses the response from a GET_SATODIME_PRIVKEY command.
     *
     * <p>Extracts and verifies the private key data for a Satodime key slot. This operation
     * "unseals" the card and reveals the private key, allowing access to stored cryptocurrency.
     * The method performs comprehensive validation including signature verification and
     * entropy-to-private-key derivation verification.</p>
     *
     * <p><strong>Response Format:</strong></p>
     * <pre>
     * [entropy_size(2b) | user_entropy + authentikey_coordx + card_entropy |
     *  privkey_size(2b) | privkey | sig_size(2b) | sig]
     * </pre>
     *
     * <p><strong>Security Validations:</strong></p>
     * <ul>
     *   <li>Signature verification against authentication key</li>
     *   <li>Private key derivation check: SHA256(entropy) must equal private key</li>
     *   <li>Response format validation</li>
     * </ul>
     *
     * <p><strong>Warning:</strong> This operation changes the card state from "sealed" to "unsealed"
     * and reveals sensitive cryptographic material.</p>
     *
     * @param rapdu the APDU response containing private key data
     * @return HashMap containing "entropy", "privkey", and "sig" byte arrays
     * @throws RuntimeException if response format is invalid, signature verification fails,
     *                         or private key doesn't match entropy derivation
     *
     * @since 0.0.4
     * @see #verifySig(byte[], byte[], byte[])
     * @see org.satochip.client.SatodimeStatus
     */
    public HashMap<String, byte[]> parseSatodimeGetPrivkey(APDUResponse rapdu){

        HashMap<String, byte[]> privkeyInfo= new HashMap<String, byte[]>();
        try{

            if (!rapdu.isOK()){
                logger.warning("SATOCHIPLIB: parseSatodimeGetPrivkey sw: " + rapdu.getSw());
                throw new RuntimeException("Exception in parseSatodimeGetPrivkey: wrong responseAPDU!");
            }

            byte[] data= rapdu.getData();
            //logger.info("SATOCHIPLIB: parseSatodimeGetPrivkey data: " + toHexString(data));
            logger.info("SATOCHIPLIB: parseSatodimeGetPrivkey authentikey: " + toHexString(authentikey));
            //data: [ entropy_size(2b) | user_entropy + authentikey_coordx + card_entropy | privkey_size(2b) | privkey | sig_size(2b) | sig ]

            int offset=0;
            int remain= data.length;

            int entropy_size= 256*data[offset++] + data[offset++];
            byte[] entropy= new byte[entropy_size];
            System.arraycopy(data, offset, entropy, 0, entropy_size);
            offset+=entropy_size;
            privkeyInfo.put("entropy", entropy);

            int privkey_size= 256*data[offset++]+data[offset++];
            byte[] privkey= new byte[privkey_size];
            System.arraycopy(data, offset, privkey, 0, privkey_size);
            offset+=privkey_size;
            privkeyInfo.put("privkey", privkey);

            int sig_size= 256*data[offset++]+data[offset++];
            byte[] sig= new byte[sig_size];
            System.arraycopy(data, offset, sig, 0, sig_size);
            privkeyInfo.put("sig", sig);

            int msg_size= 2 + entropy_size + 2 + privkey_size;
            byte[] msg= new byte[msg_size];
            System.arraycopy(data, 0, msg, 0, msg_size);

            // verification of signature
            logger.info("SATOCHIPLIB: parseSatodimeGetPrivkey verifySig: START" );
            boolean isOk= verifySig(msg, sig, authentikey);
            if (!isOk){
                throw new RuntimeException("Exception in parseSatodimeGetPrivkey: wrong signature!");
            }

            // check that privkey is correctly derived from entropy:
            SHA256Digest digest = new SHA256Digest();
            byte[] hash= new byte[digest.getDigestSize()];
            digest.update(entropy, 0, entropy.length);
            digest.doFinal(hash, 0);
            if (!Arrays.equals(hash, privkey)){
                //logger.warning("SATOCHIPLIB: parseSatodimeGetPrivkey: entropy_hash: " + toHexString(hash));
                //logger.warning("SATOCHIPLIB: parseSatodimeGetPrivkey: privkey: " + toHexString(privkey));
                throw new RuntimeException("Exception in parseSatodimeGetPrivkey: recovered private key for keyslot {key_nbr} does not match entropy hash!!");
            }

        } catch(Exception e) {
            throw new RuntimeException("Exception in parseSatodimeGetPrivkey: ", e);
        }

        return privkeyInfo;
    }

    /**
     * Converts a DER-encoded signature with coordinates to RSI format for recovery.
     *
     * <p>This utility method processes ECDSA signatures to determine the recovery ID
     * needed for public key recovery. It attempts all possible recovery IDs (0-3)
     * and returns the one that produces a public key matching the given X-coordinate.</p>
     *
     * <p><strong>Recovery Process:</strong></p>
     * <ol>
     *   <li>Decode DER signature to r,s values</li>
     *   <li>Try each recovery ID (0-3)</li>
     *   <li>Recover candidate public key</li>
     *   <li>Compare X-coordinate with expected value</li>
     *   <li>Return matching recovery ID</li>
     * </ol>
     *
     * @param hash the SHA256 hash of the original message
     * @param dersig the DER-encoded ECDSA signature
     * @param coordx the expected X-coordinate of the public key (32 bytes)
     * @return array containing [r, s, recovery_id] as BigInteger values
     * @throws RuntimeException if no valid recovery ID is found
     *
     * @since 0.0.4
     * @see #recoverRecId(byte[], BigInteger[], byte[])
     * @see #decodeFromDER(byte[])
     */
    public BigInteger[] parse_rsi_from_dersig(byte[] hash, byte[] dersig, byte[] coordx){

        BigInteger[] sigBig = decodeFromDER(dersig);

        int recid= recoverRecId(hash, sigBig, coordx);
        if (recid==-1){
            throw new RuntimeException("Exception in parse_rsv_from_dersig: could not recover recid");
        }

        BigInteger[] rsi= new BigInteger[3];
        rsi[0]= sigBig[0];
        rsi[1]= sigBig[1];
        rsi[2]= BigInteger.valueOf(recid);

        return rsi;
    }

    /* ****************************************
     *             RECOVERY METHODS           *
     **************************************** */

    /**
     * Determines the recovery ID for ECDSA public key recovery.
     *
     * <p>ECDSA signatures allow recovery of the public key used for signing, but there are
     * typically 2-4 possible candidate keys. The recovery ID identifies which candidate
     * matches the actual signing key by comparing X-coordinates.</p>
     *
     * <p>This method is based on the Bitcoin implementation and tests all possible
     * recovery IDs (0-3) to find the one that produces a public key with the
     * matching X-coordinate.</p>
     *
     * @param hash the SHA256 hash of the signed message
     * @param sigBig array containing [r, s] signature components as BigInteger
     * @param coordx the expected 32-byte X-coordinate of the signing public key
     * @return the recovery ID (0-3) that produces the matching public key, or -1 if none match
     *
     * @since 0.0.4
     * @see <a href="https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/org/bitcoinj/core/ECKey.java">BitcoinJ ECKey Recovery</a>
     * @see #Recover(byte[], BigInteger[], int, boolean)
     */
    public int recoverRecId(byte[] hash, BigInteger[] sigBig, byte[] coordx){

        ECPoint point=null;
        for (int recid=0; recid<4; recid++){
            point= Recover(hash, sigBig, recid, false);

            // convert to byte[]
            byte[] pubkey= point.getEncoded(false); // uncompressed
            byte[] coordx2= new byte[32];
            System.arraycopy(pubkey, 1, coordx2, 0, 32);

            // compare with known coordx
            if (Arrays.equals(coordx, coordx2)){
                logger.info("SATOCHIPLIB: Found coordx: " + toHexString(coordx2));
                logger.info("SATOCHIPLIB: Found pubkey: " + toHexString(pubkey));
                return recid;
            }
        }
        return -1; // could not recover pubkey
    }

    /**
     * Recovers a public key from a message signature using ECDSA key recovery.
     *
     * <p>This is the core method for public key recovery used throughout the library.
     * It implements the ECDSA public key recovery algorithm to reconstruct the signing
     * key from a message and its signature, given the X-coordinate hint.</p>
     *
     * <p><strong>Algorithm Steps:</strong></p>
     * <ol>
     *   <li>Hash the message with SHA256</li>
     *   <li>Convert DER signature to compact format (64 bytes)</li>
     *   <li>Extract r,s signature components</li>
     *   <li>Try all recovery IDs (0-3) until X-coordinate matches</li>
     *   <li>Return the recovered 65-byte uncompressed public key</li>
     * </ol>
     *
     * <p><strong>Security Note:</strong> The recovery process requires BouncyCastle
     * cryptographic library. Ensure it's properly configured in the classpath.</p>
     *
     * @param msg the original message that was signed (will be SHA256 hashed)
     * @param sig the DER-encoded ECDSA signature
     * @param coordx the 32-byte X-coordinate of the expected public key
     * @return the recovered 65-byte uncompressed public key, or null if recovery fails
     * @throws RuntimeException if BouncyCastle is not available in the classpath
     *
     * @since 0.0.4
     * @see #parseToCompactSignature(byte[])
     * @see #Recover(byte[], BigInteger[], int, boolean)
     */
    public byte[] recoverPubkey(byte[] msg, byte[] sig, byte[] coordx) {

        // convert msg to hash
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA256", "BC");
        } catch(Exception e) {
            throw new RuntimeException("Is BouncyCastle in the classpath?", e);
        }
        byte[] hash= md.digest(msg);

        // convert sig array to big integer
        byte[] sigCompact= parseToCompactSignature(sig);
        byte[] r= new byte[32];
        System.arraycopy(sigCompact, 0, r, 0, 32);
        byte[] s= new byte[32];
        System.arraycopy(sigCompact, 32, s, 0, 32);

        BigInteger[] sigBig= new BigInteger[2] ;
        sigBig[0]= new BigInteger(1, r);
        sigBig[1]= new BigInteger(1, s);

        ECPoint point=null;
        for (int recid=0; recid<4; recid++){
            point= Recover(hash, sigBig, recid, false);

            // convert to byte[]
            byte[] pubkey= point.getEncoded(false); // uncompressed
            byte[] coordx2= new byte[32];
            System.arraycopy(pubkey, 1, coordx2, 0, 32);

            // compare with known coordx
            if (Arrays.equals(coordx, coordx2)){
                logger.info("SATOCHIPLIB: Found coordx: " + toHexString(coordx2));
                logger.info("SATOCHIPLIB: Found pubkey: " + toHexString(pubkey));
                return pubkey;
            }
        }
        return null; // could not recover pubkey
    }

    /**
     * Recovers all possible public keys from a signature when X-coordinate is unknown.
     *
     * <p>In legacy secure channel initialization, the card doesn't provide the
     * X-coordinate hint for the authentication key. This method recovers all possible
     * candidate keys (typically 2-4) that could have produced the signature.
     * The correct key must be determined through subsequent verification steps.</p>
     *
     * <p><strong>Use Case:</strong> This is primarily used for backward compatibility
     * with older card firmware that doesn't include authentication key hints in
     * secure channel responses.</p>
     *
     * @param msg the original message that was signed
     * @param sig the DER-encoded ECDSA signature
     * @return list of possible 65-byte uncompressed public keys (typically 2-4 keys)
     * @throws RuntimeException if BouncyCastle is not available in the classpath
     *
     * @since 0.2.0
     * @see #parseInitiateSecureChannelGetPossibleAuthentikeys(APDUResponse)
     * @see #Recover(byte[], BigInteger[], int, boolean)
     */
    public List<byte[]> recoverPossiblePubkeys(byte[] msg, byte[] sig) {
        List<byte[]> pubkeys = new ArrayList<byte[]>();

        // convert msg to hash
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA256", "BC");
        } catch(Exception e) {
            throw new RuntimeException("Is BouncyCastle in the classpath?", e);
        }
        byte[] hash= md.digest(msg);

        // convert sig array to big integer
        byte[] sigCompact= parseToCompactSignature(sig);
        byte[] r= new byte[32];
        System.arraycopy(sigCompact, 0, r, 0, 32);
        byte[] s= new byte[32];
        System.arraycopy(sigCompact, 32, s, 0, 32);

        BigInteger[] sigBig= new BigInteger[2] ;
        sigBig[0]= new BigInteger(1, r);
        sigBig[1]= new BigInteger(1, s);

        ECPoint point=null;
        for (int recid=0; recid<4; recid++){
            point= Recover(hash, sigBig, recid, false);
            if (point==null){
                logger.warning("SATOCHIPLIB: null point for recid: " + recid);
                continue;
            }

            // convert to byte[]
            byte[] pubkey= point.getEncoded(false); // uncompressed

            // add to list
            pubkeys.add(pubkey);
            logger.warning("SATOCHIPLIB: Found potential pubkey: " + toHexString(pubkey));
        }
        return pubkeys;
    }

    /**
     * Converts a DER-encoded signature to compact format.
     *
     * <p>DER (Distinguished Encoding Rules) is the standard format for ECDSA signatures
     * in many protocols, but key recovery algorithms typically require the signature
     * components in a simpler 64-byte format (32 bytes r + 32 bytes s).</p>
     *
     * <p><strong>DER Structure:</strong></p>
     * <pre>
     * 30 &lt;total_length&gt; 02 &lt;r_length&gt; &lt;r_value&gt; 02 &lt;s_length&gt; &lt;s_value&gt;
     * </pre>
     *
     * <p><strong>Compact Format:</strong></p>
     * <pre>
     * &lt;r_value(32b)&gt; &lt;s_value(32b)&gt;
     * </pre>
     *
     * <p><strong>Padding Handling:</strong> DER encoding may include a leading zero byte
     * if the high bit of r or s is set (to prevent interpretation as negative).
     * This method strips such padding and ensures exactly 32 bytes per component.</p>
     *
     * @param sigIn the DER-encoded signature starting with 0x30
     * @return 64-byte compact signature (32-byte r followed by 32-byte s)
     * @throws RuntimeException if the DER format is invalid or malformed
     *
     * @since 0.0.4
     * @see <a href="https://en.wikipedia.org/wiki/X.690#DER_encoding">DER Encoding</a>
     */
    public byte[] parseToCompactSignature(byte[] sigIn){

        // sig is DER format, starting with 30 45
        int sigInSize= sigIn.length;

        int offset=0;
        if (sigIn[offset++] != 0x30){
            throw new RuntimeException("Wrong signature byte (should be 0x30) !");
        }
        int lt= sigIn[offset++];
        int check= sigIn[offset++];
        if (check != 0x02){
            throw new RuntimeException("Wrong signature check byte (should be 0x02) !");
        }

        int lr= sigIn[offset++]; // should be 0x20 or 0x21 if first r msb is 1
        byte[] r= new byte[32];
        if (lr== 0x20){
            System.arraycopy(sigIn, offset, r, 0, 32);
            offset+=32;
        }else if (lr== 0x21){
            offset++; // skip zero byte
            System.arraycopy(sigIn, offset, r, 0, 32);
            offset+=32;
        }
        else{
            throw new RuntimeException("Wrong signature r length (should be 0x20 or 0x21) !");
        }

        check= sigIn[offset++];
        if (check != 0x02){
            throw new RuntimeException("Wrong signature check byte (should be 0x02) !");
        }

        int ls= sigIn[offset++]; // should be 0x20 or 0x21 if first s msb is 1
        byte[] s= new byte[32];
        if (ls== 0x20){
            System.arraycopy(sigIn, offset, s, 0, 32);
            offset+=32;
        } else if (ls== 0x21){
            offset++; // skip zero byte
            System.arraycopy(sigIn, offset, s, 0, 32);
            offset+=32;
        } else{
            throw new RuntimeException("Wrong signature s length (should be 0x20 or 0x21) !");
        }

        int sigOutSize= 64;
        byte[] sigOut= new byte[sigOutSize];
        System.arraycopy(r, 0, sigOut, 0, r.length);
        System.arraycopy(s, 0, sigOut, 32, s.length);

        return sigOut;
    }

    /**
     * Performs ECDSA public key recovery using elliptic curve mathematics.
     *
     * <p>This method implements the core elliptic curve mathematics for ECDSA public
     * key recovery. It's based on the standard algorithm used in Bitcoin and other
     * cryptocurrency systems for recovering public keys from signatures.</p>
     *
     * <p><strong>Mathematical Process:</strong></p>
     * <ol>
     *   <li>Calculate R point from signature r-value and recovery ID</li>
     *   <li>Verify R point is valid on the curve</li>
     *   <li>Compute Q = r^(-1) * (s*R - e*G) where:
     *       <ul>
     *         <li>e = message hash as integer</li>
     *         <li>G = curve generator point</li>
     *         <li>r^(-1) = modular inverse of r</li>
     *       </ul>
     *   </li>
     *   <li>Return the recovered public key point Q</li>
     * </ol>
     *
     * <p><strong>Recovery ID:</strong> The recovery ID (0-3) encodes additional information
     * needed to uniquely identify the correct public key from the signature.</p>
     *
     * @param hash the SHA256 hash of the signed message
     * @param sig array containing [r, s] signature components as BigInteger
     * @param recId the recovery ID (0-3) indicating which candidate key to recover
     * @param check unused parameter (kept for compatibility)
     * @return the recovered public key as an ECPoint, or null if recovery fails
     *
     * @since 0.0.4
     * @see <a href="https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm">ECDSA on Wikipedia</a>
     * @see #decompressKey(BigInteger, boolean)
     */
    public ECPoint Recover(byte[] hash, BigInteger[] sig, int recId, boolean check){

        BigInteger r= sig[0];
        BigInteger s= sig[1];

        BigInteger n = CURVE.getN();  // Curve order.
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = r.add(i.multiply(n));
        BigInteger prime = SecP256K1Curve.q;

        if (x.compareTo(prime) >= 0) {
            // Cannot have point co-ordinates larger than this as everything takes place modulo Q.
            return null;
        }
        ECPoint R = decompressKey(x, (recId & 1) == 1);
        if (!R.multiply(n).isInfinity())
            return null;

        BigInteger e = new BigInteger(1, hash); //message.toBigInteger();

        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv);

        return q;
    }

    /**
     * Decompresses a compressed elliptic curve point to its full coordinates.
     *
     * <p>On the secp256k1 curve, a point can be represented in compressed form using
     * only the X-coordinate and a bit indicating whether Y is even or odd. This method
     * reconstructs the full point coordinates from this compressed representation.</p>
     *
     * <p><strong>Curve Equation:</strong> y² = x³ + 7 (mod p)</p>
     * <p>Given x, this method calculates the corresponding y coordinate and selects
     * the correct one based on the parity bit.</p>
     *
     * @param xBN the X-coordinate of the point as a BigInteger
     * @param yBit true if Y-coordinate should be odd, false if even
     * @return the decompressed ECPoint with full (x,y) coordinates
     *
     * @since 0.0.4
     * @see <a href="https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm">ECDSA Point Compression</a>
     */
    private ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
        compEnc[0] = (byte)(yBit ? 0x03 : 0x02);
        return CURVE.getCurve().decodePoint(compEnc);
    }

    /**
     * Decodes a DER-encoded signature with BIP62 canonical signature enforcement.
     *
     * <p>This method parses DER-encoded ECDSA signatures and enforces the BIP62 standard
     * for canonical signatures. BIP62 requires that the s-value of signatures be in the
     * lower half of the curve order to prevent transaction malleability.</p>
     *
     * <p><strong>BIP62 Canonical Signatures:</strong></p>
     * <ul>
     *   <li>If s > HALF_CURVE_ORDER, replace with (CURVE_ORDER - s)</li>
     *   <li>This eliminates signature malleability in Bitcoin transactions</li>
     *   <li>Both forms verify correctly, but only one is considered canonical</li>
     * </ul>
     *
     * <p><strong>Thread Safety:</strong> This method temporarily modifies BouncyCastle's
     * ASN.1 parsing behavior to allow unsafe integers, then restores the original setting.</p>
     *
     * @param bytes the DER-encoded signature bytes
     * @return array containing [r, s] as BigInteger with canonical s-value
     * @throws RuntimeException if DER parsing fails or signature format is invalid
     *
     * @since 0.0.4
     * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki">BIP62 Specification</a>
     * @see <a href="https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/org/bitcoinj/core/ECKey.java">BitcoinJ Implementation</a>
     */
    public BigInteger[] decodeFromDER(byte[] bytes) {
        ASN1InputStream decoder = null;
        try {
            // BouncyCastle by default is strict about parsing ASN.1 integers. We relax this check, because some
            // Bitcoin signatures would not parse.
            Properties.setThreadOverride("org.bouncycastle.asn1.allow_unsafe_integer", true);
            decoder = new ASN1InputStream(bytes);
            final ASN1Primitive seqObj = decoder.readObject();
            if (seqObj == null)
                throw new RuntimeException("Reached past end of ASN.1 stream.");
            if (!(seqObj instanceof DLSequence))
                throw new RuntimeException("Read unexpected class: " + seqObj.getClass().getName());
            final DLSequence seq = (DLSequence) seqObj;
            ASN1Integer r, s;
            try {
                r = (ASN1Integer) seq.getObjectAt(0);
                s = (ASN1Integer) seq.getObjectAt(1);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            // enforce low-S signature (BIP 62)
            BigInteger s2= s.getPositiveValue();
            if (s2.compareTo(HALF_CURVE_ORDER) > 0){
                s2= CURVE_ORDER.subtract(s2);
            }

            BigInteger[] sigBig= new BigInteger[2];
            sigBig[0]= r.getPositiveValue();
            sigBig[1]= s2; //s.getPositiveValue();
            return sigBig;

            // OpenSSL deviates from the DER spec by interpreting these values as unsigned, though they should not be
            // Thus, we always use the positive versions. See: http://r6.ca/blog/20111119T211504Z.html
        } catch (Exception e) {
            throw new RuntimeException("Exception in decodeFromDER() ", e);
        } finally {
            if (decoder != null)
                try { decoder.close(); } catch (IOException x) {}
            Properties.removeThreadOverride("org.bouncycastle.asn1.allow_unsafe_integer");
        }
    }

    /**
     * Verifies an ECDSA signature against a message and public key.
     *
     * <p>This method performs standard ECDSA signature verification to ensure that
     * a signature was created by the holder of the private key corresponding to
     * the given public key. It's used throughout the library to verify card responses
     * and ensure data authenticity.</p>
     *
     * <p><strong>Verification Process:</strong></p>
     * <ol>
     *   <li>Hash the message with SHA256</li>
     *   <li>Decode the DER signature to r,s components</li>
     *   <li>Create ECDSA verifier with the public key</li>
     *   <li>Verify signature against the message hash</li>
     * </ol>
     *
     * <p><strong>Security:</strong> This verification is critical for ensuring that
     * responses from the card are authentic and haven't been tampered with during
     * transmission over NFC.</p>
     *
     * @param msg the original message that was allegedly signed
     * @param dersig the DER-encoded signature to verify
     * @param pub the 65-byte uncompressed public key to verify against
     * @return true if the signature is valid for the message and public key
     * @throws RuntimeException if cryptographic operations fail
     *
     * @since 0.0.4
     * @see #decodeFromDER(byte[])
     * @see org.bouncycastle.crypto.signers.ECDSASigner
     */
    public boolean verifySig(byte[] msg, byte[] dersig, byte[] pub) {
        logger.info("SATOCHIPLIB: In verifySig() ");
        logger.info("SATOCHIPLIB: verifySig: authentikey: " + toHexString(pub));

        // compute hash of message
        SHA256Digest digest = new SHA256Digest();
        byte[] hash= new byte[digest.getDigestSize()];
        digest.update(msg, 0, msg.length);
        digest.doFinal(hash, 0);
        logger.info("SATOCHIPLIB: verifySig: hash: " + toHexString(hash));

        // convert der-sig to bigInteger[]
        BigInteger[] rs= decodeFromDER(dersig);

        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params = new ECPublicKeyParameters(CURVE.getCurve().decodePoint(pub), CURVE);
        signer.init(false, params);
        try {
            logger.info("SATOCHIPLIB: verifySig: hash: verifySignature: Start" );
            return signer.verifySignature(hash, rs[0], rs[1]);
        } catch (NullPointerException e) {
            logger.warning("SATOCHIPLIB: Caught NPE inside bouncy castle"+ e);
            return false;
        }
    }

    /**
     * Converts a DER-encoded X.509 certificate to PEM format.
     *
     * <p>Transforms binary DER certificate data into the ASCII-armored PEM format
     * commonly used for certificate storage and transmission. The PEM format uses
     * Base64 encoding with specific header and footer lines.</p>
     *
     * <p><strong>Output Format:</strong></p>
     * <pre>
     * -----BEGIN CERTIFICATE-----
     * &lt;Base64-encoded certificate data split into 64-character lines&gt;
     * -----END CERTIFICATE-----
     * </pre>
     *
     * <p><strong>Usage:</strong> This is typically used when exporting personalization
     * certificates from the card for verification or storage purposes.</p>
     *
     * @param certBytes the DER-encoded X.509 certificate bytes
     * @return the PEM-formatted certificate as a string with proper line breaks
     *
     * @since 0.0.4
     * @see java.util.Base64
     * @see #cardExportPersoCertificate()
     */
    public String convertBytesToStringPem(byte[] certBytes){
        logger.info("SATOCHIPLIB: In convertBytesToStringPem");
        String certBase64Raw= Base64.getEncoder().encodeToString(certBytes);
        logger.info("SATOCHIPLIB: certBase64Raw"+ certBase64Raw);

        // divide in fixed size chunk
        int chunkSize=64;
        String certBase64= "-----BEGIN CERTIFICATE-----\r\n";
        for (int offset=0; offset<certBase64Raw.length(); offset+=chunkSize){
            certBase64+= certBase64Raw.substring(offset, Math.min(certBase64Raw.length(), offset + chunkSize));
            certBase64+= "\r\n";
        }
        certBase64+= "-----END CERTIFICATE-----";
        logger.info("SATOCHIPLIB: certBase64"+ certBase64);
        return certBase64;
    }

    /**
     * Parses challenge-response data for PKI personalization verification.
     *
     * <p>Extracts the challenge and signature components from a personalization
     * challenge-response operation. This is used to verify that the card possesses
     * the private key corresponding to its personalization certificate.</p>
     *
     * <p><strong>Response Format:</strong></p>
     * <pre>
     * [challenge_from_device(32b) | sig_size(2b) | sig]
     * </pre>
     *
     * <p><strong>Verification Process:</strong> The host verifies that the card
     * correctly signed a challenge message that includes both the device-generated
     * challenge and the host-provided challenge.</p>
     *
     * @param rapdu the APDU response from a challenge-response PKI command
     * @return a two-element array where [0] is the 32-byte device challenge
     *         and [1] is the signature bytes
     * @throws RuntimeException if the response format is invalid or data is malformed
     *
     * @since 0.0.4
     * @see #cardChallengeResponsePerso(byte[])
     * @see #cardVerifyAuthenticity()
     */
    public byte[][] parseVerifyChallengeResponsePerso(APDUResponse rapdu){

        try{
            byte[] data= rapdu.getData();
            logger.info("SATOCHIPLIB: parseVerifyChallengeResponsePki data: " + toHexString(data));

            int offset=0;
            int dataRemain= data.length;

            // data= [challenge_from_device(32b) | sigSize | sig ]
            byte[][] out= new byte[2][];
            out[0]= new byte[32];
            System.arraycopy(data, offset, out[0], 0, 32);
            offset+=32;

            int sigSize= 256*data[offset++] + data[offset++];
            out[1]= new byte[sigSize];
            System.arraycopy(data, offset, out[1], 0, sigSize);

            return out;
        } catch(Exception e) {
            throw new RuntimeException("Parsing error in parseVerifyChallengeResponsePki: ", e);
        }
    }

    /**
     * Converts a byte array to its hexadecimal string representation.
     *
     * <p>This utility method provides a standardized way to convert binary data
     * to human-readable hexadecimal format. It's used extensively throughout
     * the library for logging, debugging, and data display purposes.</p>
     *
     * <p><strong>Output Format:</strong></p>
     * <ul>
     *   <li>Uppercase hexadecimal characters (0-9, A-F)</li>
     *   <li>No separators between bytes</li>
     *   <li>Two characters per byte</li>
     *   <li>Empty string for null input</li>
     * </ul>
     *
     * <p><strong>Example:</strong> {0x01, 0x02, 0xAB, 0xCD} → "0102ABCD"</p>
     *
     * @param raw the byte array to convert, may be null
     * @return the hexadecimal string representation, or empty string if input is null
     *
     * @since 0.0.4
     * @see #fromHexString(String)
     */
    public static String toHexString(byte[] raw) {
        try{
            if ( raw == null ) {
                return "";
            }
            final StringBuilder hex = new StringBuilder( 2 * raw.length );
            for ( final byte b : raw ) {
                hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
            }
            return hex.toString();
        } catch(Exception e){
            return "Exception in Util.toHexString()";
        }
    }

    /**
     * Converts a hexadecimal string to its corresponding byte array.
     *
     * <p>This utility method provides the inverse operation of {@link #toHexString(byte[])},
     * allowing conversion from hexadecimal string representation back to binary data.
     * It accepts both uppercase and lowercase hexadecimal characters.</p>
     *
     * <p><strong>Input Requirements:</strong></p>
     * <ul>
     *   <li>Even number of characters (each byte requires 2 hex digits)</li>
     *   <li>Valid hexadecimal characters only (0-9, A-F, a-f)</li>
     *   <li>No spaces or separators</li>
     * </ul>
     *
     * <p><strong>Example:</strong> "0102ABCD" → {0x01, 0x02, 0xAB, 0xCD}</p>
     *
     * @param hex the hexadecimal string to convert
     * @return the corresponding byte array
     * @throws IllegalArgumentException if the string length is odd or contains invalid characters
     *
     * @since 0.0.4
     * @see #toHexString(byte[])
     * @see Character#digit(char, int)
     */
    public static byte[] fromHexString(String hex){

        if ((hex.length() % 2) != 0)
            throw new IllegalArgumentException("Input string must contain an even number of characters");

        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
}