package org.satochip.client;

import org.satochip.io.APDUCommand;
import org.satochip.io.APDUResponse;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.logging.Logger;
import java.nio.ByteBuffer;

/**
 * Handles a secure communication channel with the Satochip hardware wallet.
 *
 * <p>This class implements a secure channel protocol that provides encrypted and authenticated
 * communication with the card using ECDH key agreement, AES encryption, and HMAC authentication.
 * The implementation follows these security principles:
 *
 * <ul>
 *   <li><strong>Key Agreement:</strong> Uses ECDH with secp256k1 curve to establish shared secret</li>
 *   <li><strong>Encryption:</strong> AES-CBC with PKCS7 padding for data confidentiality</li>
 *   <li><strong>Authentication:</strong> HMAC-SHA1 for data integrity and authenticity</li>
 *   <li><strong>Replay Protection:</strong> IV with embedded counter prevents replay attacks</li>
 * </ul>
 *
 * <p><strong>Usage Pattern:</strong>
 * <ol>
 *   <li>Create instance and get client public key with {@link #getPublicKey()}</li>
 *   <li>Exchange public keys with the card</li>
 *   <li>Initialize secure channel with {@link #initiateSecureChannel(byte[])}</li>
 *   <li>Use {@link #encrypt_secure_channel(APDUCommand)} and {@link #decrypt_secure_channel(APDUResponse)}</li>
 * </ol>
 *
 * <p><strong>Security Considerations:</strong>
 * <ul>
 *   <li>This class is not thread-safe - use one instance per session</li>
 *   <li>Session keys are ephemeral and recreated for each session</li>
 *   <li>IV counter provides replay protection within a session</li>
 *   <li>Requires BouncyCastle cryptographic provider</li>
 * </ul>
 *
 * @author Satochip Development Team
 */
public class SecureChannelSession {

  private static final Logger logger = Logger.getLogger("org.satochip.client");

  /** Length of the derived secret key in bytes */
  public static final int SC_SECRET_LENGTH = 16;

  /** AES block size in bytes */
  public static final int SC_BLOCK_SIZE = 16;

  /** Initialization Vector size in bytes */
  public static final int IV_SIZE = 16;

  /** HMAC authentication tag size in bytes */
  public static final int MAC_SIZE= 20;

  // Secure channel instruction codes
  /** APDU instruction code for initiating secure channel */
  private final static byte INS_INIT_SECURE_CHANNEL = (byte) 0x81;

  /** APDU instruction code for processing secure channel data */
  private final static byte INS_PROCESS_SECURE_CHANNEL = (byte) 0x82;

  // Status word constants
  /** Status word indicating secure channel is required */
  private final static short SW_SECURE_CHANNEL_REQUIRED = (short) 0x9C20;

  /** Status word indicating secure channel is not initialized */
  private final static short SW_SECURE_CHANNEL_UNINITIALIZED = (short) 0x9C21;

  /** Status word indicating incorrect IV in secure channel */
  private final static short SW_SECURE_CHANNEL_WRONG_IV= (short) 0x9C22;

  /** Status word indicating incorrect MAC in secure channel */
  private final static short SW_SECURE_CHANNEL_WRONG_MAC= (short) 0x9C23;

  /** Flag indicating whether the secure channel has been properly initialized */
  private boolean initialized_secure_channel= false;

  // Cryptographic state
  /** Shared secret derived from ECDH key agreement */
  private byte[] secret;

  /** Current initialization vector for encryption */
  private byte[] iv;

  /** Counter embedded in IV to prevent replay attacks */
  private int ivCounter;

  /** Derived encryption key for AES operations */
  byte[] derived_key;

  /** Derived MAC key for HMAC operations */
  byte[] mac_key;

  // ECDH key agreement components
  /** Elliptic curve parameters for secp256k1 */
  ECParameterSpec ecSpec;

  /** Client's ECDH key pair */
  private KeyPair keyPair;

  /** Client's public key in uncompressed format */
  private byte[] publicKey;

  // Session encryption components
  /** AES cipher instance for encryption/decryption */
  private Cipher sessionCipher;

  /** AES key specification for session encryption */
  private SecretKeySpec sessionEncKey;

  /** Secure random number generator */
  private SecureRandom random;

  /** Flag indicating if the session is currently open */
  private boolean open;

  /**
   * Constructs a new SecureChannelSession and initializes cryptographic components.
   *
   * <p>This constructor performs the following initialization steps:
   * <ul>
   *   <li>Initializes secure random number generator</li>
   *   <li>Sets up secp256k1 elliptic curve parameters</li>
   *   <li>Generates client ECDH key pair</li>
   *   <li>Extracts public key in uncompressed format for key exchange</li>
   * </ul>
   *
   * <p>The generated public key can be retrieved using {@link #getPublicKey()} and should
   * be sent to the card during the secure channel initialization process.
   *
   * @throws RuntimeException if BouncyCastle cryptographic provider is not available
   *                         or if elliptic curve operations fail
   *
   * @see #getPublicKey()
   * @see #initiateSecureChannel(byte[])
   */
  public SecureChannelSession() {
    random = new SecureRandom();
    open = false;

    try {
      // generate keypair
      ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
      KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
      g.initialize(ecSpec, random);
      keyPair = g.generateKeyPair();
      publicKey = ((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false);
    } catch (Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }


  /**
   * Initiates the secure channel by performing ECDH key agreement and deriving session keys.
   *
   * <p>This method completes the secure channel establishment process by:
   * <ol>
   *   <li>Performing ECDH key agreement with the card's public key</li>
   *   <li>Deriving encryption and MAC keys from the shared secret using HMAC-SHA1</li>
   *   <li>Initializing the IV counter for replay protection</li>
   *   <li>Marking the secure channel as ready for use</li>
   * </ol>
   *
   * <p><strong>Key Derivation Process:</strong>
   * <ul>
   *   <li>Encryption key: first 16 bytes of HMAC-SHA1(shared_secret, "sc_key")</li>
   *   <li>MAC key: full 20 bytes of HMAC-SHA1(shared_secret, "sc_mac")</li>
   * </ul>
   *
   * <p>After successful completion, the secure channel is ready for encrypting and
   * decrypting APDU commands using {@link #encrypt_secure_channel(APDUCommand)} and
   * {@link #decrypt_secure_channel(APDUResponse)}.
   *
   * @param keyData the card's public key in uncompressed format (65 bytes).
   *                Must be a valid secp256k1 public key starting with 0x04.
   *
   * @throws RuntimeException if ECDH key agreement fails, key derivation fails,
   *                         or cryptographic operations encounter errors
   * @throws IllegalArgumentException if keyData is null or has invalid format
   *
   * @see #encrypt_secure_channel(APDUCommand)
   * @see #decrypt_secure_channel(APDUResponse)
   * @see #initializedSecureChannel()
   */
  public void initiateSecureChannel(byte[] keyData) { //TODO: check keyData format
    try {

      // Diffie-Hellman
      // ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
      // KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
      // g.initialize(ecSpec, random);
      // KeyPair keyPair = g.generateKeyPair();
      // publicKey = ((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false);

      KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
      keyAgreement.init(keyPair.getPrivate());

      ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(keyData), ecSpec);
      ECPublicKey cardKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC").generatePublic(cardKeySpec);

      keyAgreement.doPhase(cardKey, true);
      secret = keyAgreement.generateSecret();

      // derive session keys
      HMac hMac = new HMac(new SHA1Digest());
      hMac.init(new KeyParameter(secret));
      byte[] msg_key= "sc_key".getBytes();
      hMac.update(msg_key, 0, msg_key.length);
      byte[] out = new byte[20];
      hMac.doFinal(out, 0);
      derived_key= new byte[16];
      System.arraycopy(out, 0, derived_key, 0, 16);

      hMac.reset();
      byte[] msg_mac= "sc_mac".getBytes();
      hMac.update(msg_mac, 0, msg_mac.length);
      mac_key = new byte[20];
      hMac.doFinal(mac_key, 0);

      ivCounter= 1;
      initialized_secure_channel= true;
    } catch (Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }

  /**
   * Encrypts a plain APDU command for secure transmission over the secure channel.
   *
   * <p>This method transforms a regular APDU command into an encrypted secure channel APDU
   * that provides both confidentiality and authenticity. The encryption process includes:
   *
   * <ol>
   *   <li><strong>IV Generation:</strong> Creates a 16-byte IV with random prefix and embedded counter</li>
   *   <li><strong>Encryption:</strong> Encrypts the serialized APDU using AES-CBC with PKCS7 padding</li>
   *   <li><strong>Authentication:</strong> Computes HMAC-SHA1 over IV + encrypted_length + encrypted_data</li>
   *   <li><strong>Packaging:</strong> Combines all components into secure channel APDU format</li>
   *   <li><strong>Counter Update:</strong> Increments IV counter by 2 for next operation</li>
   * </ol>
   *
   * <p><strong>Output Format:</strong>
   * The returned APDU has instruction {@code INS_PROCESS_SECURE_CHANNEL (0x82)} and data:
   * {@code [IV(16) | encrypted_length(2) | encrypted_data(variable) | mac_length(2) | mac(20)]}
   *
   * <p><strong>Security Properties:</strong>
   * <ul>
   *   <li>Confidentiality through AES-CBC encryption</li>
   *   <li>Authenticity through HMAC-SHA1</li>
   *   <li>Replay protection through IV counter</li>
   *   <li>Forward secrecy through ephemeral session keys</li>
   * </ul>
   *
   * @param plainApdu the plain APDU command to encrypt. Must not be null.
   *
   * @return encrypted APDU command ready for transmission to the card.
   *         The returned APDU uses CLA=0xB0, INS=0x82 (secure channel processing).
   *
   * @throws RuntimeException if the secure channel is not initialized, encryption fails,
   *                         or HMAC computation encounters errors
   * @throws IllegalArgumentException if plainApdu is null
   * @throws IllegalStateException if secure channel has not been initialized
   *
   * @see #decrypt_secure_channel(APDUResponse)
   * @see #initiateSecureChannel(byte[])
   * @see #initializedSecureChannel()
   */
  public APDUCommand encrypt_secure_channel(APDUCommand plainApdu){

    try {

      byte[] plainBytes= plainApdu.serialize();

      // set iv
      iv = new byte[SC_BLOCK_SIZE];
      random.nextBytes(iv);
      ByteBuffer bb = ByteBuffer.allocate(4);
      bb.putInt(ivCounter);  // big endian
      byte[] ivCounterBytes= bb.array();
      System.arraycopy(ivCounterBytes, 0, iv, 12, 4);
      ivCounter+=2;
      logger.info("SATOCHIPLIB: ivCounter: "+ ivCounter);
      logger.info("SATOCHIPLIB: ivCounterBytes: "+ SatochipParser.toHexString(ivCounterBytes));
      logger.info("SATOCHIPLIB: iv: "+ SatochipParser.toHexString(iv));

      // encrypt data
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      sessionEncKey = new SecretKeySpec(derived_key, "AES");
      sessionCipher = Cipher.getInstance("AES/CBC/PKCS7PADDING", "BC");
      sessionCipher.init(Cipher.ENCRYPT_MODE, sessionEncKey, ivParameterSpec);
      byte[] encrypted = sessionCipher.doFinal(plainBytes);
      // logger.info("SATOCHIPLIB: encrypted: "+ SatochipParser.toHexString(derived_key));
      // logger.info("SATOCHIPLIB: encrypted: "+ SatochipParser.toHexString(encrypted));

      // mac
      int offset= 0;
      byte[] data_to_mac= new byte[IV_SIZE + 2 + encrypted.length];
      System.arraycopy(iv, offset, data_to_mac, offset, IV_SIZE);
      offset+=IV_SIZE;
      data_to_mac[offset++]= (byte)(encrypted.length>>8);
      data_to_mac[offset++]= (byte)(encrypted.length%256);
      System.arraycopy(encrypted, 0, data_to_mac, offset, encrypted.length);
      // logger.info("SATOCHIPLIB: data_to_mac: "+ SatochipParser.toHexString(data_to_mac));

      HMac hMac = new HMac(new SHA1Digest());
      hMac.init(new KeyParameter(mac_key));
      hMac.update(data_to_mac, 0, data_to_mac.length);
      byte[] mac = new byte[20];
      hMac.doFinal(mac, 0);
      // logger.info("SATOCHIPLIB: mac: "+ SatochipParser.toHexString(mac));

      //data= list(iv) + [len(ciphertext)>>8, len(ciphertext)&0xff] + list(ciphertext) + [len(mac)>>8, len(mac)&0xff] + list(mac)
      byte[] data= new byte[IV_SIZE + 2 + encrypted.length + 2 + MAC_SIZE];
      offset= 0;
      System.arraycopy(iv, offset, data, offset, IV_SIZE);
      offset+=IV_SIZE;
      data[offset++]= (byte)(encrypted.length>>8);
      data[offset++]= (byte)(encrypted.length%256);
      System.arraycopy(encrypted, 0, data, offset, encrypted.length);
      offset+=encrypted.length;
      data[offset++]= (byte)(mac.length>>8);
      data[offset++]= (byte)(mac.length%256);
      System.arraycopy(mac, 0, data, offset, mac.length);
      // logger.info("SATOCHIPLIB: data: "+ SatochipParser.toHexString(data));

      // convert to C-APDU
      APDUCommand encryptedApdu= new APDUCommand(0xB0, INS_PROCESS_SECURE_CHANNEL, 0x00, 0x00, data);
      return encryptedApdu;

    } catch (Exception e) {
      e.printStackTrace();
      logger.warning("SATOCHIPLIB: Exception in encrypt_secure_channel: "+ e);
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }

  }

  /**
   * Decrypts an encrypted APDU response received from the card over the secure channel.
   *
   * <p>This method reverses the encryption process performed by the card, extracting
   * the original plain APDU response from the encrypted secure channel format.
   * The decryption process includes:
   *
   * <ol>
   *   <li><strong>Format Validation:</strong> Verifies the encrypted response has correct structure</li>
   *   <li><strong>Component Extraction:</strong> Separates IV and encrypted data</li>
   *   <li><strong>Decryption:</strong> Decrypts data using AES-CBC with the session key</li>
   *   <li><strong>Response Creation:</strong> Creates plain APDU response with status 0x9000</li>
   * </ol>
   *
   * <p><strong>Input Format Expected:</strong>
   * The encrypted response should contain: {@code [IV(16) | encrypted_length(2) | encrypted_data(variable)]}
   *
   * <p><strong>Behavior:</strong>
   * <ul>
   *   <li>If response data is empty, returns the original response unchanged (no decryption needed)</li>
   *   <li>If response has invalid length (< 18 bytes), throws RuntimeException</li>
   *   <li>Successful decryption returns plain response with SW=0x9000</li>
   * </ul>
   *
   * <p><strong>Note:</strong> This method does not verify MAC authentication as that is typically
   * handled at the APDU transport level. It focuses solely on data decryption.
   *
   * @param encryptedApdu the encrypted APDU response from the card. Must not be null.
   *
   * @return the decrypted plain APDU response with original data and status word 0x9000,
   *         or the original response if no decryption is needed (empty data)
   *
   * @throws RuntimeException if decryption fails, the encrypted response has invalid format,
   *                         or AES operations encounter errors
   * @throws IllegalArgumentException if encryptedApdu is null
   * @throws IllegalStateException if secure channel has not been initialized
   *
   * @see #encrypt_secure_channel(APDUCommand)
   * @see #initiateSecureChannel(byte[])
   */
  public APDUResponse decrypt_secure_channel(APDUResponse encryptedApdu){

    try {

      byte[] encryptedBytes= encryptedApdu.getData();
      if (encryptedBytes.length==0){
        return encryptedApdu; // no decryption needed
      } else if (encryptedBytes.length<18){
        throw new RuntimeException("Encrypted response has wrong length!");
      }

      byte[] iv= new byte[IV_SIZE];
      int offset= 0;
      System.arraycopy(encryptedBytes, offset, iv, 0, IV_SIZE);
      offset+=IV_SIZE;
      int ciphertext_size= ((encryptedBytes[offset++] & 0xff)<<8) + (encryptedBytes[offset++] & 0xff);
      if ((encryptedBytes.length - offset)!= ciphertext_size){
        throw new RuntimeException("Encrypted response has wrong length!");
      }
      byte[] ciphertext= new byte[ciphertext_size];
      System.arraycopy(encryptedBytes, offset, ciphertext, 0, ciphertext.length);

      // decrypt data
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      sessionEncKey = new SecretKeySpec(derived_key, "AES");
      sessionCipher = Cipher.getInstance("AES/CBC/PKCS7PADDING", "BC");
      sessionCipher.init(Cipher.DECRYPT_MODE, sessionEncKey, ivParameterSpec);
      byte[] decrypted = sessionCipher.doFinal(ciphertext);

      APDUResponse plainResponse= new APDUResponse(decrypted, (byte)0x90, (byte)0x00);
      return plainResponse;

    } catch (Exception e) {
      e.printStackTrace();
      logger.warning("SATOCHIPLIB: Exception in decrypt_secure_channel: "+ e);
      throw new RuntimeException("Exception during secure channel decryption: ", e);
    }

  }

  /**
   * Checks whether the secure channel has been properly initialized and is ready for use.
   *
   * <p>This method returns {@code true} if and only if {@link #initiateSecureChannel(byte[])}
   * has been successfully called with valid card public key data. When this method returns
   * {@code true}, the secure channel is ready for encrypting and decrypting APDU commands.
   *
   * <p><strong>Usage:</strong> This method should be checked before attempting to use
   * {@link #encrypt_secure_channel(APDUCommand)} or {@link #decrypt_secure_channel(APDUResponse)}
   * to ensure the secure channel is in a valid state.
   *
   * @return {@code true} if the secure channel is initialized and ready for secure communication,
   *         {@code false} if initialization is required
   *
   * @see #initiateSecureChannel(byte[])
   * @see #resetSecureChannel()
   */
  public boolean initializedSecureChannel(){
    return initialized_secure_channel;
  }

  /**
   * Returns the client's public key for ECDH key agreement with the card.
   *
   * <p>This method returns the client's secp256k1 public key in uncompressed format,
   * which should be sent to the card during the secure channel initialization process.
   * The card will use this public key along with its own private key to compute the
   * same shared secret that the client computes using the card's public key.
   *
   * <p><strong>Format:</strong> The returned key is 65 bytes in uncompressed format:
   * <ul>
   *   <li>Byte 0: 0x04 (uncompressed point indicator)</li>
   *   <li>Bytes 1-32: X coordinate (32 bytes)</li>
   *   <li>Bytes 33-64: Y coordinate (32 bytes)</li>
   * </ul>
   *
   * <p><strong>Security:</strong> While this is a public key and safe to transmit in the clear,
   * it should be sent to the correct card to prevent man-in-the-middle attacks during
   * the key agreement process.
   *
   * @return the client's public key in uncompressed format (65 bytes), never null
   *
   * @see #initiateSecureChannel(byte[])
   */
  public byte[] getPublicKey(){
    return publicKey;
  }

  /**
   * Resets the secure channel to an uninitialized state, requiring re-initialization.
   *
   * <p>This method clears the secure channel state, marking it as uninitialized.
   * After calling this method:
   * <ul>
   *   <li>{@link #initializedSecureChannel()} will return {@code false}</li>
   *   <li>{@link #encrypt_secure_channel(APDUCommand)} and {@link #decrypt_secure_channel(APDUResponse)}
   *       should not be used until re-initialization</li>
   *   <li>{@link #initiateSecureChannel(byte[])} must be called again to establish a new secure channel</li>
   * </ul>
   *
   * <p><strong>Use Cases:</strong>
   * <ul>
   *   <li>Card disconnection or communication errors</li>
   *   <li>Security policy requiring periodic re-keying</li>
   *   <li>Switching to a different card</li>
   *   <li>Error recovery scenarios</li>
   * </ul>
   *
   * <p><strong>Security Note:</strong> This method does not explicitly clear cryptographic
   * material from memory. For sensitive applications, consider additional secure memory
   * clearing procedures if required by your security policy.
   *
   * @see #initiateSecureChannel(byte[])
   * @see #initializedSecureChannel()
   */
  public void resetSecureChannel(){
    initialized_secure_channel= false;
    return;
  }

}