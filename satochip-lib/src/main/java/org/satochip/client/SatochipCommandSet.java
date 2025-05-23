package org.satochip.client;

import org.bitcoinj.core.Base58;
import org.bitcoinj.core.Sha256Hash;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.satochip.client.seedkeeper.*;
import org.satochip.io.*;
import org.bouncycastle.util.encoders.Hex;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.cert.PKIXParameters;
import java.security.KeyStore;
import java.security.PublicKey;

import static org.satochip.client.Constants.*;

/**
 * Command set for communicating with Satochip, SeedKeeper, and Satodime applets.
 *
 * <p>This class provides a comprehensive interface for sending APDU commands to the smart card
 * applets. Each method corresponds to specific APDU commands as defined in the application
 * documentation. The class handles secure channel communication, PIN management, BIP32 operations,
 * and various cryptographic functions.</p>
 *
 * <p>Key features include:</p>
 * <ul>
 *   <li>Automatic secure channel establishment and management</li>
 *   <li>PIN verification and management</li>
 *   <li>BIP32 hierarchical deterministic wallet operations</li>
 *   <li>Digital signature generation and verification</li>
 *   <li>PKI certificate management</li>
 *   <li>Satodime key management operations</li>
 *   <li>SeedKeeper secret storage operations</li>
 * </ul>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * CardChannel channel = new MyCardChannel();
 * SatochipCommandSet commandSet = new SatochipCommandSet(channel);
 *
 * // Select the applet
 * APDUResponse response = commandSet.cardSelect();
 *
 * // Verify PIN
 * byte[] pin = "123456".getBytes();
 * commandSet.cardVerifyPIN(pin);
 *
 * // Get extended key
 * byte[][] keyData = commandSet.cardBip32GetExtendedKey("m/44'/0'/0'/0/0");
 * }</pre>
 *
 * @author Satochip Team
 * @see CardChannel
 * @see APDUCommand
 * @see APDUResponse
 */
public class SatochipCommandSet {

    private static final Logger logger = Logger.getLogger("org.satochip.client");

    private final CardChannel apduChannel;
    private SecureChannelSession secureChannel;
    private ApplicationStatus status;
    private SatochipParser parser = null;

    private byte[] pin0 = null;
    private List<byte[]> possibleAuthentikeys = new ArrayList<byte[]>();
    private byte[] authentikey = null;
    private String authentikeyHex = null;
    private String defaultBip32path = null;
    private byte[] extendedKey = null;
    private byte[] extendedChaincode = null;
    private String extendedKeyHex = null;
    private byte[] extendedPrivKey = null;
    private String extendedPrivKeyHex = null;

    // Satodime, SeedKeeper or Satochip?
    private String cardType = null;
    private String certPem = null; // PEM certificate of device, if any

    // satodime
    SatodimeStatus satodimeStatus = null;

    public static final byte[] SATOCHIP_AID = Hex.decode("5361746f43686970"); //SatoChip
    public static final byte[] SEEDKEEPER_AID = Hex.decode("536565644b6565706572"); //SeedKeeper
    public static final byte[] SATODIME_AID = Hex.decode("5361746f44696d65"); //SatoDime

    public final static byte DERIVE_P1_SOURCE_MASTER = (byte) 0x00;
    public final static byte DERIVE_P1_SOURCE_PARENT = (byte) 0x40;
    public final static byte DERIVE_P1_SOURCE_CURRENT = (byte) 0x80;

    /**
     * Creates a new SatochipCommandSet instance with the specified APDU channel.
     *
     * <p>This constructor initializes all necessary components including the secure channel
     * session, parser, and Satodime status. The logger is set to WARNING level by default.</p>
     *
     * @param apduChannel the APDU channel for communication with the smart card.
     *                   Must not be null and should be properly connected.
     * @throws NullPointerException if apduChannel is null
     * @see CardChannel
     * @see SecureChannelSession
     * @see SatochipParser
     */
    public SatochipCommandSet(CardChannel apduChannel) {
        this.apduChannel = apduChannel;
        this.secureChannel = new SecureChannelSession();
        this.parser = new SatochipParser();
        this.satodimeStatus = new SatodimeStatus();
        logger.setLevel(Level.WARNING);
    }

    /**
     * Sets the logging level using a string identifier.
     *
     * <p>Supported levels:</p>
     * <ul>
     *   <li>"info" - Enables detailed logging information</li>
     *   <li>"warning" - Shows only warnings and errors (default)</li>
     * </ul>
     *
     * <p>Any unrecognized level defaults to WARNING.</p>
     *
     * @param level the logging level as a string ("info" or "warning")
     * @see #setLoggerLevel(Level)
     */
    public void setLoggerLevel(String level) {
        switch (level) {
            case "info":
                logger.setLevel(Level.INFO);
                break;
            case "warning":
                logger.setLevel(Level.WARNING);
                break;
            default:
                logger.setLevel(Level.WARNING);
                break;
        }
    }

    /**
     * Sets the logging level using a java.util.logging.Level object.
     *
     * <p>This method provides more granular control over logging levels
     * compared to the string-based version.</p>
     *
     * @param level the logging level to set
     * @see Level
     * @see #setLoggerLevel(String)
     */
    public void setLoggerLevel(Level level) {
        logger.setLevel(level);
    }

    /**
     * Returns the current application status information.
     *
     * <p>The application status contains information about the card's state including
     * setup status, seed initialization, secure channel requirements, and version information.
     * This information is populated after a successful SELECT command.</p>
     *
     * @return the application status object, or null if no successful SELECT command
     *         has been executed using this command set
     * @see ApplicationStatus
     * @see #cardSelect()
     */
    public ApplicationStatus getApplicationStatus() {
        return status;
    }

    /**
     * Returns the current Satodime status after refreshing it from the card.
     *
     * <p>This method automatically calls {@link #satodimeGetStatus()} to ensure
     * the returned status is current. The status includes information about
     * key slots, unlock counters, and overall Satodime state.</p>
     *
     * @return the current Satodime status
     * @see SatodimeStatus
     * @see #satodimeGetStatus()
     */
    public SatodimeStatus getSatodimeStatus() {
        this.satodimeGetStatus();
        return this.satodimeStatus;
    }

    /**
     * Returns the Satodime unlock secret.
     *
     * <p>The unlock secret is a 20-byte value used to generate unlock codes
     * for various Satodime operations. This secret should be kept confidential
     * as it provides control over the Satodime device.</p>
     *
     * @return the 20-byte unlock secret, or null if not available
     * @see #setSatodimeUnlockSecret(byte[])
     */
    public byte[] getSatodimeUnlockSecret() {
        return this.satodimeStatus.getUnlockSecret();
    }

    /**
     * Sets the Satodime unlock secret.
     *
     * <p>This method stores the unlock secret that will be used for generating
     * unlock codes for Satodime operations. The secret must be exactly 20 bytes.</p>
     *
     * @param unlockSecret the 20-byte unlock secret to set
     * @throws IllegalArgumentException if unlockSecret is not exactly 20 bytes
     * @see #getSatodimeUnlockSecret()
     */
    public void setSatodimeUnlockSecret(byte[] unlockSecret) {
        this.satodimeStatus.setUnlockSecret(unlockSecret);
    }

    /****************************************
     *                AUTHENTIKEY           *
     ****************************************/

    /**
     * Retrieves the device's authentication key (authentikey).
     *
     * <p>The authentikey is a unique public key that identifies the device and is used
     * for authentication purposes. If not already cached, this method will automatically
     * retrieve it from the card using {@link #cardGetAuthentikey()}.</p>
     *
     * @return the 65-byte uncompressed authentication public key
     * @see #cardGetAuthentikey()
     * @see #getAuthentikeyHex()
     */
    public byte[] getAuthentikey() {
        if (authentikey == null) {
            cardGetAuthentikey();
        }
        return authentikey;
    }

    /**
     * Retrieves the device's authentication key as a hexadecimal string.
     *
     * <p>This is a convenience method that returns the authentikey in hexadecimal
     * format. If the authentikey is not cached, it will be retrieved from the card.</p>
     *
     * @return the authentication key as a hexadecimal string
     * @see #getAuthentikey()
     * @see #cardGetAuthentikey()
     */
    public String getAuthentikeyHex() {
        if (authentikeyHex == null) {
            cardGetAuthentikey();
        }
        return authentikeyHex;
    }

    /**
     * Retrieves the BIP32 authentication key from the card.
     *
     * <p>This method uses the BIP32_GET_AUTHENTIKEY command to retrieve the
     * authentication key. This is an alternative method to {@link #getAuthentikey()}
     * that uses a different APDU command.</p>
     *
     * @return the 65-byte uncompressed authentication public key
     * @see #cardBip32GetAuthentikey()
     * @see #getBip32AuthentikeyHex()
     */
    public byte[] getBip32Authentikey() {
        if (authentikey == null) {
            cardBip32GetAuthentikey();
        }
        return authentikey;
    }

    /**
     * Retrieves the BIP32 authentication key as a hexadecimal string.
     *
     * <p>Convenience method that returns the BIP32 authentikey in hexadecimal format.</p>
     *
     * @return the BIP32 authentication key as a hexadecimal string
     * @see #getBip32Authentikey()
     * @see #cardBip32GetAuthentikey()
     */
    public String getBip32AuthentikeyHex() {
        if (authentikeyHex == null) {
            cardBip32GetAuthentikey();
        }
        return authentikeyHex;
    }

    /**
     * Returns the list of possible authentication keys.
     *
     * <p>During secure channel establishment, multiple possible authentication keys
     * may be recovered due to ECDSA signature properties. This method returns all
     * possible candidates.</p>
     *
     * @return list of possible authentication keys (each 65 bytes)
     * @see #cardInitiateSecureChannel()
     */
    public List<byte[]> getPossibleAuthentikeys(){
        return this.possibleAuthentikeys;
    }

    /**
     * Returns the parser instance used for APDU response parsing.
     *
     * <p>The parser handles the conversion of raw APDU response data into
     * structured objects and performs cryptographic operations like signature
     * verification and key recovery.</p>
     *
     * @return the SatochipParser instance
     * @see SatochipParser
     */
    public SatochipParser getParser() {
        return parser;
    }

    /**
     * Sets the default BIP32 derivation path for operations.
     *
     * <p>This path will be used as a default when no specific path is provided
     * to BIP32 operations. The path should be in the format "m/44'/0'/0'/0/0".</p>
     *
     * @param bip32path the default BIP32 path string (e.g., "m/44'/0'/0'/0/0")
     * @see #cardBip32GetExtendedKey()
     */
    public void setDefaultBip32path(String bip32path) {
        defaultBip32path = bip32path;
    }

    /**
     * Sets the secure channel session for this command set.
     *
     * <p>This is typically used internally and should not be called by client code
     * unless implementing custom secure channel handling.</p>
     *
     * @param secureChannel the secure channel session to use
     * @see SecureChannelSession
     */
    protected void setSecureChannel(SecureChannelSession secureChannel) {
        this.secureChannel = secureChannel;
    }

    /**
     * Transmits an APDU command to the card with automatic secure channel and PIN handling.
     *
     * <p>This method handles the complete APDU transmission process including:</p>
     * <ul>
     *   <li>Automatic status checking and retrieval</li>
     *   <li>Secure channel establishment when required</li>
     *   <li>APDU encryption/decryption for secure commands</li>
     *   <li>Automatic PIN verification when needed</li>
     *   <li>Error handling and retry logic</li>
     * </ul>
     *
     * <p>The method will automatically retry operations in certain error conditions
     * such as uninitialized secure channels or required PIN authentication.</p>
     *
     * @param plainApdu the APDU command to transmit
     * @return the response from the card, decrypted if necessary
     * @throws RuntimeException if communication fails or an unrecoverable error occurs
     * @see APDUCommand
     * @see APDUResponse
     * @see #cardInitiateSecureChannel()
     * @see #cardVerifyPIN()
     */
    public APDUResponse cardTransmit(APDUCommand plainApdu) {

        // we try to transmit the APDU until we receive the answer or we receive an unrecoverable error
        boolean isApduTransmitted = false;
        do {
            try {
                byte[] apduBytes = plainApdu.serialize();
                byte ins = apduBytes[1];
                boolean isEncrypted = false;

                // check if status available
                if (status == null) {
                    APDUCommand statusCapdu = new APDUCommand(0xB0, INS_GET_STATUS, 0x00, 0x00, new byte[0]);
                    APDUResponse statusRapdu = apduChannel.send(statusCapdu);
                    status = new ApplicationStatus(statusRapdu);
                    logger.info("SATOCHIPLIB: Status cardGetStatus:" + status.toString());
                }

                APDUCommand capdu = null;
                if (status.needsSecureChannel() && (ins != 0xA4) && (ins != 0x81) && (ins != 0x82) && (ins != INS_GET_STATUS)) {

                    if (!secureChannel.initializedSecureChannel()) {
                        cardInitiateSecureChannel();
                        logger.info("SATOCHIPLIB: secure Channel initiated!");
                    }
                    // encrypt apdu
                    //logger.info("SATOCHIPLIB: Capdu before encryption:"+ plainApdu.toHexString());
                    capdu = secureChannel.encrypt_secure_channel(plainApdu);
                    isEncrypted = true;
                    //logger.info("SATOCHIPLIB: Capdu encrypted:"+ capdu.toHexString());
                } else {
                    // plain adpu
                    capdu = plainApdu;
                }

                APDUResponse rapdu = apduChannel.send(capdu);
                int sw12 = rapdu.getSw();

                // check answer
                if (sw12 == 0x9000) { // ok!
                    if (isEncrypted) {
                        // decrypt
                        //logger.info("SATOCHIPLIB: Rapdu encrypted:"+ rapdu.toHexString());
                        rapdu = secureChannel.decrypt_secure_channel(rapdu);
                        //logger.info("SATOCHIPLIB: Rapdu decrypted:"+ rapdu.toHexString());
                    }
                    isApduTransmitted = true; // leave loop
                    return rapdu;
                }
                // PIN authentication is required
                else if (sw12 == 0x9C06) {
                    cardVerifyPIN();
                }
                // SecureChannel is not initialized
                else if (sw12 == 0x9C21) {
                    secureChannel.resetSecureChannel();
                } else {
                    // cannot resolve issue at this point
                    isApduTransmitted = true; // leave loop
                    return rapdu;
                }

            } catch (Exception e) {
                logger.warning("SATOCHIPLIB: Exception in cardTransmit: " + e);
                return new APDUResponse(new byte[0], (byte) 0x00, (byte) 0x00); // return empty APDUResponse
            }

        } while (!isApduTransmitted);

        return new APDUResponse(new byte[0], (byte) 0x00, (byte) 0x00); // should not happen
    }

    /**
     * Disconnects from the card and resets internal state.
     *
     * <p>This method cleans up the session by:</p>
     * <ul>
     *   <li>Resetting the secure channel</li>
     *   <li>Clearing the application status</li>
     *   <li>Clearing cached PIN data</li>
     * </ul>
     *
     * <p>This should be called when the card is removed or when the session
     * needs to be terminated.</p>
     */
    public void cardDisconnect() {
        secureChannel.resetSecureChannel();
        status = null;
        pin0 = null;
    }

    /**
     * Selects an applet on the card by trying multiple known AIDs.
     *
     * <p>This method attempts to select applets in the following order:</p>
     * <ol>
     *   <li>Satochip applet</li>
     *   <li>SeedKeeper applet</li>
     *   <li>Satodime applet</li>
     * </ol>
     *
     * <p>The first successfully selected applet determines the card type.</p>
     *
     * @return the APDU response from the successful SELECT command
     * @throws IOException if communication with the card fails
     * @see #cardSelect(String)
     */
    public APDUResponse cardSelect() throws IOException {

        APDUResponse rapdu = cardSelect("satochip");
        if (rapdu.getSw() != 0x9000) {
            rapdu = cardSelect("seedkeeper");
            if (rapdu.getSw() != 0x9000) {
                rapdu = cardSelect("satodime");
                if (rapdu.getSw() != 0x9000) {
                    this.cardType = "unknown";
                    logger.warning("SATOCHIPLIB: CardSelect: could not select a known applet");
                }
            }
        }

        return rapdu;
    }

    /**
     * Selects a specific applet type on the card.
     *
     * <p>Supported card types:</p>
     * <ul>
     *   <li>"satochip" - Satochip wallet applet</li>
     *   <li>"seedkeeper" - SeedKeeper secret storage applet</li>
     *   <li>"satodime" - Satodime bearer bond applet</li>
     * </ul>
     *
     * @param cardType the type of applet to select
     * @return the APDU response from the SELECT command
     * @throws IOException if communication with the card fails
     * @see #cardSelect()
     */
    public APDUResponse cardSelect(String cardType) throws IOException {

        APDUCommand selectApplet;
        if (cardType.equals("satochip")) {
            selectApplet = new APDUCommand(0x00, 0xA4, 0x04, 0x00, SATOCHIP_AID);
        } else if (cardType.equals("seedkeeper")) {
            selectApplet = new APDUCommand(0x00, 0xA4, 0x04, 0x00, SEEDKEEPER_AID);
        } else {
            selectApplet = new APDUCommand(0x00, 0xA4, 0x04, 0x00, SATODIME_AID);
        }

        logger.info("SATOCHIPLIB: C-APDU cardSelect:" + selectApplet.toHexString());
        APDUResponse respApdu = apduChannel.send(selectApplet);
        logger.info("SATOCHIPLIB: R-APDU cardSelect:" + respApdu.toHexString());

        if (respApdu.getSw() == 0x9000) {
            this.cardType = cardType;
            logger.info("SATOCHIPLIB: Satochip-java: CardSelect: found a " + this.cardType);
        }
        return respApdu;
    }

    /**
     * Retrieves the current status of the applet.
     *
     * <p>The status includes information about:</p>
     * <ul>
     *   <li>Protocol and applet version numbers</li>
     *   <li>Setup completion status</li>
     *   <li>Seed initialization status</li>
     *   <li>Secure channel requirements</li>
     *   <li>2FA status</li>
     *   <li>PIN retry counters</li>
     * </ul>
     *
     * <p>This method updates the internal status object and should be called
     * after significant operations to ensure status is current.</p>
     *
     * @return the APDU response containing status information
     * @see ApplicationStatus
     * @see #getApplicationStatus()
     */
    public APDUResponse cardGetStatus() {
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_STATUS, 0x00, 0x00, new byte[0]);

        logger.info("SATOCHIPLIB: C-APDU cardGetStatus:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardGetStatus:" + respApdu.toHexString());

        status = new ApplicationStatus(respApdu);
        logger.info("SATOCHIPLIB: Status from cardGetStatus:" + status.toString());

        return respApdu;
    }

    /**
     * Initiates a secure channel with the card.
     *
     * <p>This method performs the secure channel establishment process:</p>
     * <ol>
     *   <li>Sends the client's public key to the card</li>
     *   <li>Receives the card's public key and authentication signatures</li>
     *   <li>Performs ECDH key agreement</li>
     *   <li>Derives session encryption and MAC keys</li>
     *   <li>Recovers possible authentication keys</li>
     * </ol>
     *
     * <p>After successful completion, all subsequent commands will be automatically
     * encrypted when required by the applet.</p>
     *
     * @return list of possible authentication keys recovered during the process
     * @throws IOException if communication with the card fails
     * @see SecureChannelSession
     * @see #getPossibleAuthentikeys()
     */
    public List<byte[]> cardInitiateSecureChannel() throws IOException {

        byte[] pubkey = secureChannel.getPublicKey();

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_INIT_SECURE_CHANNEL, 0x00, 0x00, pubkey);

        logger.info("SATOCHIPLIB: C-APDU cardInitiateSecureChannel:" + plainApdu.toHexString());
        APDUResponse respApdu = apduChannel.send(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardInitiateSecureChannel:" + respApdu.toHexString());

        byte[] keyData = parser.parseInitiateSecureChannel(respApdu);
        possibleAuthentikeys = parser.parseInitiateSecureChannelGetPossibleAuthentikeys(respApdu);
        // setup secure channel
        secureChannel.initiateSecureChannel(keyData);

        return possibleAuthentikeys;
    }

    /**
     * Exports the device's authentication public key.
     *
     * <p>This method retrieves the device's authentication key using the
     * EXPORT_AUTHENTIKEY command. The key is cached for future use and
     * can be accessed via {@link #getAuthentikey()}.</p>
     *
     * <p><strong>Compatibility:</strong></p>
     * <ul>
     *   <li>Satochip v0.12 and higher</li>
     *   <li>All Seedkeeper versions</li>
     *   <li>All Satodime versions</li>
     * </ul>
     *
     * @return the 65-byte uncompressed authentication public key
     * @see #getAuthentikey()
     * @see #getAuthentikeyHex()
     */
    public byte[] cardGetAuthentikey() {

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_EXPORT_AUTHENTIKEY, 0x00, 0x00, new byte[0]);
        logger.info("SATOCHIPLIB: C-APDU cardExportAuthentikey:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardExportAuthentikey:" + respApdu.toHexString());

        // parse and recover pubkey
        authentikey = parser.parseBip32GetAuthentikey(respApdu);
        authentikeyHex = parser.toHexString(authentikey);
        logger.info("SATOCHIPLIB: Authentikey from cardExportAuthentikey:" + authentikeyHex);

        return authentikey;
    }

    /**
     * Retrieves the BIP32 authentication key from the card.
     *
     * <p>This method uses the BIP32_GET_AUTHENTIKEY command to retrieve the
     * authentication key. The returned key is cached for future access.</p>
     *
     * <p>Note: this method is only available for Satochip applet</p>
     *
     * @return the APDU response containing the authentication key data
     * @see #getBip32Authentikey()
     * @see #getBip32AuthentikeyHex()
     */
    public APDUResponse cardBip32GetAuthentikey() {

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_BIP32_GET_AUTHENTIKEY, 0x00, 0x00, new byte[0]);
        logger.info("SATOCHIPLIB: C-APDU cardBip32GetAuthentikey:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardBip32GetAuthentikey:" + respApdu.toHexString());

        // parse and recover pubkey
        authentikey = parser.parseBip32GetAuthentikey(respApdu);
        authentikeyHex = parser.toHexString(authentikey);
        logger.info("SATOCHIPLIB: Authentikey from cardBip32GetAuthentikey:" + authentikeyHex);

        return respApdu;
    }

    /**
     * Exports the PKI public key from the card.
     *
     * <p>This method retrieves the public key used for PKI operations and
     * device authentication. The key is typically used for certificate-based
     * authentication and device identity verification.</p>
     *
     * @return the APDU response containing the PKI public key
     * @see #cardExportPersoCertificate()
     * @see #cardChallengeResponsePerso(byte[])
     */
    public APDUResponse cardExportPkiPubkey() {

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_EXPORT_PKI_PUBKEY, 0x00, 0x00, new byte[0]);
        logger.info("SATOCHIPLIB: C-APDU cardExportPkiPubkey:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardExportPkiPubkey:" + respApdu.toHexString());

        // parse and recover pubkey
        authentikey = parser.parseExportPkiPubkey(respApdu);
        authentikeyHex = parser.toHexString(authentikey);
        logger.info("SATOCHIPLIB: Authentikey from cardExportPkiPubkey:" + authentikeyHex);

        return respApdu;
    }

    /**
     * Retrieves the human-readable label assigned to the card.
     *
     * <p>This method returns the custom label that has been set for the card,
     * which can be used to identify the device in user interfaces. If no label
     * has been set, returns a default value.</p>
     *
     * <p>Labels are useful for:</p>
     * <ul>
     *   <li>Distinguishing between multiple cards</li>
     *   <li>User-friendly device identification</li>
     *   <li>Organizational purposes</li>
     *   <li>Card management systems</li>
     * </ul>
     *
     * <p><strong>Compatibility:</strong></p>
     * <ul>
     *   <li>Satochip v0.12 and higher</li>
     *   <li>All Seedkeeper versions</li>
     *   <li>All Satodime versions</li>
     * </ul>
     *
     * @return the card's label as a UTF-8 string, or "(none)" if not set, or "(unknown)" on error
     * @see #setCardLabel(String)
     */
    public String getCardLabel() {
        logger.info("SATOCHIPLIB: getCardLabel START");

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_CARD_LABEL, 0x00, 0x01, new byte[0]);
        logger.info("SATOCHIPLIB: C-APDU getCardLabel:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU getCardLabel:"+ respApdu.toHexString());
        int sw = respApdu.getSw();
        String label;
        if (sw == 0x9000){
            byte labelSize = respApdu.getData()[0];
            try {
                label = new String(respApdu.getData(), 1, labelSize, StandardCharsets.UTF_8);
            } catch (Exception e) {
                logger.warning("SATOCHIPLIB: getCardLabel UnicodeDecodeError while decoding card label!");
                label = new String(respApdu.getData(), 1, respApdu.getData().length - 1, StandardCharsets.UTF_8);
            }
        } else if (sw == 0x6D00) {
            logger.info("SATOCHIPLIB: getCardLabel  label not set:" + sw);
            label = "(none)";
        } else {
            logger.warning("SATOCHIPLIB: getCardLabel Error while recovering card label:" + sw);
            label = "(unknown)";
        }
        return label;
    }

    /**
     * Sets a human-readable label for the card.
     *
     * <p>This method assigns a custom UTF-8 label to the card for identification
     * purposes. The label is stored persistently on the card and can be retrieved
     * using {@link #getCardLabel()}.</p>
     *
     * <p>Label guidelines:</p>
     * <ul>
     *   <li>Use descriptive names for easy identification</li>
     *   <li>Keep length reasonable for display purposes</li>
     *   <li>Use UTF-8 compatible characters</li>
     *   <li>Avoid sensitive information in labels</li>
     * </ul>
     *
     * <p><strong>Compatibility:</strong></p>
     * <ul>
     *   <li>Satochip v0.12 and higher</li>
     *   <li>All Seedkeeper versions</li>
     *   <li>All Satodime versions</li>
     * </ul>
     *
     * @param label the UTF-8 label to assign to the card
     * @return true if the label was set successfully, false otherwise
     * @see #getCardLabel()
     */
    public Boolean setCardLabel(String label) {
        logger.info("SATOCHIPLIB: setCardLabel START");

        byte[] labelData = label.getBytes(StandardCharsets.UTF_8);
        byte[] data = new byte[1 + labelData.length];
        data[0] = (byte) labelData.length;
        System.arraycopy(labelData, 0, data, 1, labelData.length);

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_CARD_LABEL, 0x00, 0x00, data);
        logger.info("SATOCHIPLIB: C-APDU setCardLabel:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU setCardLabel:"+ respApdu.toHexString());
        int sw = respApdu.getSw();
        return sw == 0x9000;
    }
    
    /****************************************
     *              CARD MGMT               *
     ****************************************/

    /**
     * Performs initial setup of the card with simplified parameters.
     *
     * <p>This is a convenience method that sets up the card with:</p>
     * <ul>
     *   <li>The specified PIN0 and retry count</li>
     *   <li>Randomly generated PIN1, PUK0, and PUK1</li>
     *   <li>Single retry attempts for PUK operations</li>
     * </ul>
     *
     * <p>This method is suitable for basic setup scenarios where only the main PIN
     * needs to be specified.</p>
     *
     * @param pin_tries0 number of retry attempts for PIN0 (typically 3-5)
     * @param pin0 the PIN0 value to set (4-16 bytes recommended)
     * @return the APDU response from the setup command
     * @see #cardSetup(byte, byte, byte[], byte[], byte, byte, byte[], byte[])
     */
    public APDUResponse cardSetup(byte pin_tries0, byte[] pin0) {

        // use random values for pin1, ublk0, ublk1
        SecureRandom random = new SecureRandom();
        byte[] ublk0 = new byte[8];
        byte[] ublk1 = new byte[8];
        byte[] pin1 = new byte[8];
        random.nextBytes(ublk0);
        random.nextBytes(ublk1);
        random.nextBytes(pin1);

        byte ublk_tries0 = (byte) 0x01;
        byte ublk_tries1 = (byte) 0x01;
        byte pin_tries1 = (byte) 0x01;

        return cardSetup(pin_tries0, ublk_tries0, pin0, ublk0, pin_tries1, ublk_tries1, pin1, ublk1);
    }

    /**
     * Performs comprehensive initial setup of the card with full parameter control.
     *
     * <p>This method initializes the card with all security parameters including:</p>
     * <ul>
     *   <li>PIN0 and PIN1 with their respective retry counters</li>
     *   <li>PUK0 and PUK1 (unblock keys) with their retry counters</li>
     *   <li>Memory allocation settings (deprecated)</li>
     *   <li>Access control list settings (deprecated)</li>
     * </ul>
     *
     * <p>After successful setup, the PIN0 is automatically cached for subsequent operations.
     * For Satodime cards, the setup response also updates the internal status.</p>
     *
     * <p><strong>Warning:</strong> This operation can only be performed once per card.
     * Ensure all parameters are correct before calling this method.</p>
     *
     * @param pin_tries0 number of retry attempts for PIN0 before blocking
     * @param ublk_tries0 number of retry attempts for PUK0 before permanent blocking
     * @param pin0 the primary PIN value (4-16 bytes recommended)
     * @param ublk0 the primary unblock key (PUK0) value
     * @param pin_tries1 number of retry attempts for PIN1 before blocking
     * @param ublk_tries1 number of retry attempts for PUK1 before permanent blocking
     * @param pin1 the secondary PIN value
     * @param ublk1 the secondary unblock key (PUK1) value
     * @return the APDU response from the setup command
     * @throws IllegalStateException if the card is already set up
     * @see #cardSetup(byte, byte[])
     */
    public APDUResponse cardSetup(
            byte pin_tries0, byte ublk_tries0, byte[] pin0, byte[] ublk0,
            byte pin_tries1, byte ublk_tries1, byte[] pin1, byte[] ublk1) {

        byte[] pin = {0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30}; //default pin
        byte cla = (byte) 0xB0;
        byte ins = INS_SETUP;
        byte p1 = 0;
        byte p2 = 0;

        // data=[pin_length(1) | pin |
        //        pin_tries0(1) | ublk_tries0(1) | pin0_length(1) | pin0 | ublk0_length(1) | ublk0 |
        //        pin_tries1(1) | ublk_tries1(1) | pin1_length(1) | pin1 | ublk1_length(1) | ublk1 |
        //        memsize(2) | memsize2(2) | ACL(3) |
        //        option_flags(2) | hmacsha160_key(20) | amount_limit(8)]
        int optionsize = 0;
        int option_flags = 0; // do not use option (mostly deprecated)
        int offset = 0;
        int datasize = 16 + pin.length + pin0.length + pin1.length + ublk0.length + ublk1.length + optionsize;
        byte[] data = new byte[datasize];

        data[offset++] = (byte) pin.length;
        System.arraycopy(pin, 0, data, offset, pin.length);
        offset += pin.length;
        // pin0 & ublk0
        data[offset++] = pin_tries0;
        data[offset++] = ublk_tries0;
        data[offset++] = (byte) pin0.length;
        System.arraycopy(pin0, 0, data, offset, pin0.length);
        offset += pin0.length;
        data[offset++] = (byte) ublk0.length;
        System.arraycopy(ublk0, 0, data, offset, ublk0.length);
        offset += ublk0.length;
        // pin1 & ublk1
        data[offset++] = pin_tries1;
        data[offset++] = ublk_tries1;
        data[offset++] = (byte) pin1.length;
        System.arraycopy(pin1, 0, data, offset, pin1.length);
        offset += pin1.length;
        data[offset++] = (byte) ublk1.length;
        System.arraycopy(ublk1, 0, data, offset, ublk1.length);
        offset += ublk1.length;

        // memsize default (deprecated)
        data[offset++] = (byte) 00;
        data[offset++] = (byte) 32;
        data[offset++] = (byte) 00;
        data[offset++] = (byte) 32;

        // ACL (deprecated)
        data[offset++] = (byte) 0x01;
        data[offset++] = (byte) 0x01;
        data[offset++] = (byte) 0x01;

        APDUCommand plainApdu = new APDUCommand(cla, ins, p1, p2, data);
        //logger.info("SATOCHIPLIB: C-APDU cardSetup:" + plainApdu.toHexString());
        logger.info("SATOCHIPLIB: C-APDU cardSetup");
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardSetup:" + respApdu.toHexString());

        if (respApdu.isOK()) {
            setPin0(pin0);

            if (this.cardType.equals("satodime")) { // cache values
                this.satodimeStatus.updateStatusFromSetup(respApdu);
            }
        }

        return respApdu;
    }

    /**
     * Sends a factory reset command to the card.
     * Factory reset is triggered by sending a fixed number of successive reset command to the card.
     * The user must remove the card from the reader between each reset command.
     *
     * <p>Factory reset resets the card to its factory state, erasing all data including:</p>
     * <ul>
     *   <li>All stored keys and seeds</li>
     *   <li>PIN and PUK settings</li>
     *   <li>All user data and configurations</li>
     * </ul>
     *
     * <p><strong>Warning:</strong> Factory reset is irreversible and will permanently
     * destroy all user data on the card. Use with extreme caution.</p>
     *
     * <p>Note: This command must be sent without secure channel encryption and
     * should not be mixed with other commands to ensure proper execution.</p>
     *
     * <p><strong>Compatibility: </strong></p>
     * <ul>
     *   <li>Satochip v0.12-0.4 and higher</li>
     *   <li>Seedkeeper v0.1 </li>
     *   <li>Not supported on satodime</li>
     * </ul>
     *
     * @return the APDU response from the reset command
     * @throws Exception if the reset operation fails
     */
    public APDUResponse cardSendResetCommand() throws Exception {
        byte[] data = new byte[]{};

        APDUCommand plainApdu = new APDUCommand(
                0xB0,
                INS_RESET_TO_FACTORY,
                0x00,
                0x00,
                data
        );

        // reset command must be sent in clear, without other commands interferring between reset commands
        logger.warning("SATOCHIPLIB: C-APDU cardSendResetCommand:" + plainApdu.toHexString());
        APDUResponse respApdu = apduChannel.send(plainApdu);
        logger.warning("SATOCHIPLIB: R-APDU cardSendResetCommand:" + respApdu.toHexString());

        return respApdu;
    }

    /****************************************
     *             PIN MGMT                  *
     ****************************************/

    /**
     * Stores a PIN0 value for subsequent automatic authentication.
     *
     * <p>This method caches the PIN0 value which will be used automatically
     * when PIN verification is required. The PIN is stored in memory until
     * the session is disconnected or explicitly cleared.</p>
     *
     * @param pin the PIN0 value to cache (typically 4-16 bytes)
     * @see #cardVerifyPIN()
     * @see #cardDisconnect()
     */
    public void setPin0(byte[] pin) {
        this.pin0 = new byte[pin.length];
        System.arraycopy(pin, 0, this.pin0, 0, pin.length);
    }

    /**
     * Verifies a PIN against the card with explicit PIN parameter.
     *
     * <p>This method verifies the provided PIN with the card. If the PIN is null,
     * it will use the cached PIN0 value. Successful verification allows access to
     * protected operations.</p>
     *
     * <p>The method handles various authentication error conditions:</p>
     * <ul>
     *   <li>Wrong PIN with remaining attempts</li>
     *   <li>Wrong PIN (legacy format)</li>
     *   <li>Blocked PIN requiring PUK</li>
     *   <li>Factory reset condition</li>
     * </ul>
     *
     * <p>Upon successful verification, the PIN is cached for future operations.</p>
     *
     * @param pin the PIN to verify, or null to use cached PIN0
     * @return the APDU response from the verification command
     * @throws WrongPINException if the PIN is incorrect, includes retry count
     * @throws WrongPINLegacyException if the PIN is incorrect (legacy format)
     * @throws BlockedPINException if the PIN is blocked and requires PUK
     * @throws ResetToFactoryException if the card has been reset to factory state
     * @throws RuntimeException if no PIN is available and none was provided
     * @see #setPin0(byte[])
     * @see #cardVerifyPIN()
     */
    public APDUResponse cardVerifyPIN(byte[] pin) throws Exception {

        byte[] mypin = pin;
        if (mypin == null){
            if (pin0 == null) {
                // TODO: specific exception
                throw new RuntimeException("PIN required!");
            }
            mypin = pin0;
        }

        try {
            APDUCommand plainApdu = new APDUCommand(0xB0, INS_VERIFY_PIN, 0x00, 0x00, mypin);
            //logger.info("SATOCHIPLIB: C-APDU cardVerifyPIN:" + plainApdu.toHexString());
            logger.info("SATOCHIPLIB: C-APDU cardVerifyPIN");
            APDUResponse rapdu = this.cardTransmit(plainApdu);
            logger.info("SATOCHIPLIB: R-APDU cardVerifyPIN:" + rapdu.toHexString());

            rapdu.checkAuthOK();
            this.pin0 = mypin; // cache new pin
            return rapdu;

        } catch (WrongPINException e) {
            this.pin0 = null;
            throw e;
        } catch (WrongPINLegacyException e) {
            this.pin0 = null;
            throw e;
        } catch (BlockedPINException e) {
            this.pin0 = null;
            throw e;
        } catch (APDUException e){
            this.pin0 = null;
            throw e;
        } catch (Exception e){
            this.pin0 = null;
            throw e;
        }
    }

    /**
     * Verifies the cached PIN0 against the card.
     *
     * <p>This is a convenience method that uses the previously cached PIN0 value
     * for verification. The PIN must have been set using {@link #setPin0(byte[])}
     * or a previous successful verification.</p>
     *
     * @return the APDU response from the verification command
     * @throws Exception if verification fails or no PIN is cached
     * @see #cardVerifyPIN(byte[])
     * @see #setPin0(byte[])
     */
    public APDUResponse cardVerifyPIN() throws Exception {
        return cardVerifyPIN(this.pin0);
    }

    /**
     * Changes the PIN0 from an old value to a new value.
     *
     * <p>This method allows changing the PIN0 by providing both the current PIN
     * and the desired new PIN. The operation requires that the current PIN is
     * correct and that the card is not in a blocked state.</p>
     *
     * <p>Upon successful completion, the new PIN is automatically cached for
     * future operations.</p>
     *
     * @param oldPin the current PIN0 value
     * @param newPin the new PIN0 value to set
     * @return the APDU response from the change command
     * @throws WrongPINException if the old PIN is incorrect
     * @throws WrongPINLegacyException if the old PIN is incorrect (legacy format)
     * @throws BlockedPINException if the PIN is blocked
     * @throws Exception if the operation fails
     * @see #setPin0(byte[])
     */
    public APDUResponse cardChangePin(byte[] oldPin, byte[] newPin) throws Exception {
        logger.info("SATOCHIPLIB: changeCardPin START");

        byte[] data = new byte[1 + oldPin.length + 1 + newPin.length];
        data[0] = (byte) oldPin.length;
        System.arraycopy(oldPin, 0, data, 1, oldPin.length);
        data[1 + oldPin.length] = (byte) newPin.length;
        System.arraycopy(newPin, 0, data, 2 + oldPin.length, newPin.length);
        setPin0(newPin);
        try{
            APDUCommand plainApdu = new APDUCommand(0xB0, INS_CHANGE_PIN, 0x00, 0x00, data);
            //logger.info("SATOCHIPLIB: C-APDU changeCardPin:"+ plainApdu.toHexString());
            logger.info("SATOCHIPLIB: C-APDU changeCardPin");
            APDUResponse rapdu = this.cardTransmit(plainApdu);
            logger.info("SATOCHIPLIB: R-APDU changeCardPin:"+ rapdu.toHexString());

            rapdu.checkAuthOK();
            return rapdu;

        } catch (WrongPINException e) {
            this.pin0 = null;
            throw e;
        } catch (WrongPINLegacyException e) {
            this.pin0 = null;
            throw e;
        } catch (BlockedPINException e) {
            this.pin0 = null;
            throw e;
        } catch (APDUException e){
            this.pin0 = null;
            throw e;
        } catch (Exception e){
            this.pin0 = null;
            throw e;
        }
    }

    /**
     * Unblocks a blocked PIN using the corresponding PUK (PIN Unblock Key).
     *
     * <p>When a PIN becomes blocked due to too many incorrect attempts, this method
     * can be used to unblock it using the PUK. The PUK itself has limited retry
     * attempts, and if exhausted, may trigger a factory reset.</p>
     *
     * <p>Successful unblocking typically resets the PIN retry counter, allowing
     * normal PIN operations to resume.</p>
     *
     * @param puk the PIN Unblock Key (PUK) to use for unblocking
     * @return the APDU response from the unblock command
     * @throws WrongPINException if the PUK is incorrect
     * @throws WrongPINLegacyException if the PUK is incorrect (legacy format)
     * @throws BlockedPINException if the PUK itself is blocked
     * @throws ResetToFactoryException if the card triggers a factory reset
     * @throws Exception if the operation fails
     */
    public APDUResponse cardUnblockPin(byte[] puk) throws Exception {
        APDUCommand plainApdu = new APDUCommand(
                0xB0,
                INS_UNBLOCK_PIN,
                0x00,
                0x00,
                puk
        );

        try{
            //logger.info("SATOCHIPLIB: C-APDU cardUnblockPin:" + plainApdu.toHexString());
            logger.info("SATOCHIPLIB: C-APDU cardUnblockPin");
            APDUResponse rapdu = this.cardTransmit(plainApdu);
            logger.info("SATOCHIPLIB: R-APDU cardUnblockPin:" + rapdu.toHexString());

            rapdu.checkAuthOK();
            return rapdu;

        } catch (WrongPINException e) {
            this.pin0 = null;
            throw e;
        } catch (WrongPINLegacyException e) {
            this.pin0 = null;
            throw e;
        } catch (BlockedPINException e) {
            this.pin0 = null;
            throw e;
        } catch (ResetToFactoryException e) {
            this.pin0 = null;
            throw e;
        } catch (APDUException e){
            this.pin0 = null;
            throw e;
        } catch (Exception e){
            this.pin0 = null;
            throw e;
        }

    }

    /****************************************
     *                BIP32                 *
     ****************************************/

    /**
     * Imports a master seed into the card for BIP32 operations.
     *
     * <p>This method stores a master seed on the card which will be used as the root
     * for all BIP32 hierarchical deterministic key derivations. The seed should be
     * generated using a cryptographically secure random number generator.</p>
     *
     * <p>Common seed lengths:</p>
     * <ul>
     *   <li>16 bytes (128 bits) - minimum recommended</li>
     *   <li>24 bytes (192 bits) - good security</li>
     *   <li>32 bytes (256 bits) - maximum security</li>
     * </ul>
     *
     * <p><strong>Warning:</strong> Ensure the seed is properly backed up before importing.</p>
     *
     * @param masterseed the master seed bytes to import (16-64 bytes recommended)
     * @return the APDU response from the import command
     * @see #cardResetSeed(byte[], byte[])
     * @see #cardBip32GetExtendedKey(String, Byte, Integer)
     */
    public APDUResponse cardBip32ImportSeed(byte[] masterseed) {
        //TODO: check seed (length...)
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_BIP32_IMPORT_SEED, masterseed.length, 0x00, masterseed);

        //logger.info("SATOCHIPLIB: C-APDU cardBip32ImportSeed:" + plainApdu.toHexString());
        logger.info("SATOCHIPLIB: C-APDU cardBip32ImportSeed");
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardBip32ImportSeed:" + respApdu.toHexString());

        return respApdu;
    }

    /**
     * Resets the BIP32 seed with PIN and optional 2FA challenge-response.
     *
     * <p>This method clears the existing BIP32 seed from the card, allowing a new
     * seed to be imported. The operation requires PIN verification and optionally
     * supports 2FA challenge-response authentication for additional security.</p>
     *
     * <p>After successful reset, a new seed can be imported using
     * {@link #cardBip32ImportSeed(byte[])}.</p>
     *
     * @param pin the PIN0 for authentication
     * @param chalresponse optional 2FA challenge response (20 bytes), or null if not using 2FA
     * @return the APDU response from the reset command
     * @throws IllegalArgumentException if chalresponse is not null and not exactly 20 bytes
     * @see #cardBip32ImportSeed(byte[])
     */
    public APDUResponse cardResetSeed(byte[] pin, byte[] chalresponse) {

        byte p1 = (byte) pin.length;
        byte[] data;
        if (chalresponse == null) {
            data = new byte[pin.length];
            System.arraycopy(pin, 0, data, 0, pin.length);
        } else if (chalresponse.length == 20) {
            data = new byte[pin.length + 20];
            int offset = 0;
            System.arraycopy(pin, 0, data, offset, pin.length);
            offset += pin.length;
            System.arraycopy(chalresponse, 0, data, offset, chalresponse.length);
        } else {
            throw new RuntimeException("Wrong challenge-response length (should be 20)");
        }

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_BIP32_RESET_SEED, p1, 0x00, data);
        logger.info("SATOCHIPLIB: C-APDU cardResetSeed:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardResetSeed:" + respApdu.toHexString());
        // TODO: check SW code for particular status

        return respApdu;
    }

    /**
     * Derives an extended key using the default BIP32 path.
     *
     * <p>This convenience method uses the default BIP32 path set via
     * {@link #setDefaultBip32path(String)} or falls back to "m/44'/60'/0'/0/0"
     * if no default is set.</p>
     *
     * @return array containing [public_key, chain_code] where public_key is 65 bytes
     *         and chain_code is 32 bytes
     * @throws Exception if the derivation fails or no seed is available
     * @see #cardBip32GetExtendedKey(String, Byte, Integer)
     * @see #setDefaultBip32path(String)
     */
    public byte[][] cardBip32GetExtendedKey() throws Exception {
        if (defaultBip32path == null) {
            defaultBip32path = "m/44'/60'/0'/0/0";
        }
        return cardBip32GetExtendedKey(defaultBip32path, null, null);
    }

    /**
     * Derives an extended key for the specified BIP32 path with optional parameters.
     *
     * <p>This method performs BIP32 hierarchical deterministic key derivation on the card.
     * The path specifies which key to derive from the master seed. The method supports
     * various derivation options and can handle both public and private key derivation.</p>
     *
     * <p>Path format examples:</p>
     * <ul>
     *   <li>"m/44'/0'/0'/0/0" - Bitcoin mainnet first account, first address</li>
     *   <li>"m/44'/60'/0'/0/0" - Ethereum mainnet first account, first address</li>
     *   <li>"m/49'/0'/0'/0/0" - Bitcoin P2SH-P2WPKH</li>
     * </ul>
     *
     * <p>The apostrophe (') indicates hardened derivation (adds 0x80000000 to the index).</p>
     *
     * @param stringPath the BIP32 derivation path as a string (maximum 10 levels deep)
     * @param flags optional derivation flags:
     *              <ul>
     *                <li>0x40 - derive public key (default)</li>
     *                <li>0x42 - derive private key</li>
     *                <li>0x44 - BIP85 derivation</li>
     *              </ul>
     * @param sid optional SeedKeeper secret ID for secure derivation
     * @return array containing [key, chain_code] where key is 33 bytes (compressed public)
     *         or 65 bytes (uncompressed public) or 32 bytes (private), and chain_code is 32 bytes
     * @throws Exception if the path is invalid, too deep, or derivation fails
     * @see #cardBip32GetExtendedKey()
     * @see #cardBip32GetXpub(String, long, Integer)
     */
    public byte[][] cardBip32GetExtendedKey(String stringPath, Byte flags, Integer sid) throws Exception {
        logger.warning("SATOCHIPLIB: cardBip32GetExtendedKey");
        Bip32Path parsedPath = new Bip32Path(stringPath);
        if (parsedPath.getDepth() > 10) {
            throw new Exception("Path length exceeds maximum depth of 10: " + parsedPath.getDepth());
        }

        byte p1 = parsedPath.getDepth().byteValue();
        byte optionFlags = (byte) 0x40;
        if (flags != null) {
            optionFlags = flags;
        }
        byte p2 = optionFlags;

        byte[] data = parsedPath.getBytes();

        if (sid != null) {
            data = Arrays.copyOf(data, data.length + 2);
            data[data.length - 2] = (byte) ((sid >> 8) & 0xFF);
            data[data.length - 1] = (byte) (sid & 0xFF);
        }

        while (true) {
            APDUCommand plainApdu = new APDUCommand(
                    0xB0,
                    INS_BIP32_GET_EXTENDED_KEY,
                    p1,
                    p2,
                    data
            );
            logger.warning("SATOCHIPLIB: C-APDU cardBip32GetExtendedKey:" + plainApdu.toHexString());
            APDUResponse respApdu = this.cardTransmit(plainApdu);
            logger.warning("SATOCHIPLIB: R-APDU cardBip32GetExtendedKey:" + respApdu.toHexString());
            if (respApdu.getSw() == 0x9C01) {
                logger.warning("SATOCHIPLIB: cardBip32GetExtendedKey: Reset memory...");
                // reset memory flag
                p2 = (byte) (p2 ^ 0x80);
                plainApdu = new APDUCommand(
                        0xB0,
                        INS_BIP32_GET_EXTENDED_KEY,
                        p1,
                        p2,
                        data
                );
                respApdu = this.cardTransmit(plainApdu);
                // reset the flag then restart
                p2 = optionFlags;
                continue;
            }
            // other (unexpected) error
            if (respApdu.getSw() != 0x9000) {
                throw new Exception("SATOCHIPLIB: cardBip32GetExtendedKey:" +
                        "Unexpected error during BIP32 derivation. SW: " +
                        respApdu.getSw() + " " + respApdu.toHexString()
                );
            }
            // success
            if (respApdu.getSw() == 0x9000) {
                logger.warning("SATOCHIPLIB: cardBip32GetExtendedKey: return 0x9000...");
                byte[] response = respApdu.getData();
                if ((optionFlags & 0x04) == 0x04) { // BIP85
                    //todo: enable?
                    logger.warning("SATOCHIPLIB: cardBip32GetExtendedKey: in BIP85");
                    extendedKey = parser.parseBip85GetExtendedKey(respApdu)[0];
                    extendedKeyHex = parser.toHexString(extendedKey);
                } else if ((optionFlags & 0x02) == 0x00) { // BIP32 pubkey
                    logger.warning("SATOCHIPLIB: cardBip32GetExtendedKey: in BIP39");
                    if ((response[32] & 0x80) == 0x80) {
                        logger.info("SATOCHIPLIB: cardBip32GetExtendedKey: Child Derivation optimization...");
                        throw new Exception("Unsupported legacy option during BIP32 derivation");
                    }
                    byte[][] extendedKeyData = parser.parseBip32GetExtendedKey(respApdu);
                    extendedKey = extendedKeyData[0];// todo: return array
                    extendedChaincode = extendedKeyData[1];
                    extendedKeyHex = parser.toHexString(extendedKey);
                    return extendedKeyData;
                } else { // BIP32 privkey
                    byte[][] extendedPrivKeyData = parser.parseBip32GetExtendedKey(respApdu);
                    extendedPrivKey = extendedPrivKeyData[0];
                    extendedPrivKeyHex = parser.toHexString(extendedPrivKey);
                    return extendedPrivKeyData;
                }
            }
        }
    }

    /**
     * Returns the cached extended key from the last derivation operation.
     *
     * <p>This method is primarily used for testing purposes and returns the
     * extended key that was cached from the most recent call to
     * {@link #cardBip32GetExtendedKey(String, Byte, Integer)}.</p>
     *
     * @return the cached extended key bytes, or null if no derivation has been performed
     * @see #cardBip32GetExtendedKey(String, Byte, Integer)
     */
    public byte[] getExtendedKey() {
        return extendedKey;
    }

    /**
     * Derives and formats a BIP32 extended public key (xpub) for the specified path.
     *
     * <p>This method performs BIP32 key derivation and formats the result as a
     * Base58Check-encoded extended public key string. The xpub format includes:</p>
     * <ul>
     *   <li>Version bytes (4 bytes) - determines network and key type</li>
     *   <li>Depth (1 byte) - how many derivations from master</li>
     *   <li>Parent fingerprint (4 bytes) - first 4 bytes of parent key hash</li>
     *   <li>Child number (4 bytes) - derivation index of this key</li>
     *   <li>Chain code (32 bytes) - for further derivations</li>
     *   <li>Public key (33 bytes) - compressed public key</li>
     * </ul>
     *
     * <p>Common xtype values:</p>
     * <ul>
     *   <li>0x0488B21E - Bitcoin mainnet P2PKH (xpub)</li>
     *   <li>0x043587CF - Bitcoin testnet P2PKH (tpub)</li>
     *   <li>0x049D7CB2 - Bitcoin mainnet P2SH-P2WPKH (ypub)</li>
     *   <li>0x04B24746 - Bitcoin mainnet P2WPKH (zpub)</li>
     * </ul>
     *
     * @param path the BIP32 derivation path (e.g., "m/44'/0'/0'")
     * @param xtype the extended key version type for network/format identification
     * @param sid optional SeedKeeper secret ID for secure derivation
     * @return the Base58Check-encoded extended public key string
     * @throws Exception if derivation fails or path is invalid
     * @see #cardBip32GetExtendedKey(String, Byte, Integer)
     */
    public String cardBip32GetXpub(String path, long xtype, Integer sid) throws Exception {
        logger.warning("SATOCHIPLIB: cardBip32GetXpub");

        byte[] childPubkey, childChaincode;
        byte optionFlags = (byte) 0x40;

        // Get extended key
        logger.warning("SATOCHIPLIB: cardBip32GetXpub: getting card cardBip32GetExtendedKey");
        cardBip32GetExtendedKey(path, optionFlags, sid);
        logger.warning("SATOCHIPLIB: cardBip32GetXpub: got it "+ extendedKey.length);

        childPubkey = extendedKey;
        childChaincode = extendedChaincode;

        // Pubkey should be in compressed form
        if (extendedKey.length != 33) {
            childPubkey = parser.compressPubKey(extendedKey);
        }

        Bip32Path parsedPath = new Bip32Path(path);
        int depth = parsedPath.getDepth();
        byte[] bytePath = parsedPath.getBytes();
        byte[] fingerprintBytes = new byte[4];
        byte[] childNumberBytes = new byte[4];

        if (depth > 0) {
            // Get parent info
            String parentPath = Bip32Path.getBip32PathParentPath(path);
            logger.warning("SATOCHIPLIB: cardBip32GetXpub: parentPathString: "+ parentPath);

            cardBip32GetExtendedKey(parentPath, optionFlags, sid);
            byte[] parentPubkeyBytes = extendedKey;

            // Pubkey should be in compressed form
            if (parentPubkeyBytes.length != 33) {
                parentPubkeyBytes = parser.compressPubKey(parentPubkeyBytes);
            }

            fingerprintBytes = Arrays.copyOfRange(digestRipeMd160(Sha256Hash.hash(parentPubkeyBytes)), 0, 4);
            childNumberBytes = Arrays.copyOfRange(bytePath, bytePath.length - 4, bytePath.length);
        }

        byte[] xtypeBytes = ByteBuffer.allocate(4).putInt((int) xtype).array();
        byte[] xpubBytes = new byte[78];
        System.arraycopy(xtypeBytes, 0, xpubBytes, 0, 4);
        xpubBytes[4] = (byte) depth;
        System.arraycopy(fingerprintBytes, 0, xpubBytes, 5, 4);
        System.arraycopy(childNumberBytes, 0, xpubBytes, 9, 4);
        System.arraycopy(childChaincode, 0, xpubBytes, 13, 32);
        System.arraycopy(childPubkey, 0, xpubBytes, 45, 33);

        if (xpubBytes.length != 78) {
            throw new Exception("wrongXpubLength " + xpubBytes.length + " " + 78);
        }

        String xpub = encodeChecked(xpubBytes);
//        String xpub = Base58.encodeChecked(0, xpubBytes);
        logger.warning("SATOCHIPLIB: cardBip32GetXpub: xpub: " + xpub);
        return xpub;
    }

    /**
     * Encodes bytes with Base58Check encoding.
     *
     * <p>This method adds a 4-byte checksum to the input data and encodes the result
     * using Base58 encoding. This is the standard encoding used for Bitcoin addresses
     * and extended keys.</p>
     *
     * @param bytes the bytes to encode
     * @return the Base58Check-encoded string
     * @see #calculateChecksum(byte[])
     */
    private String encodeChecked(byte[] bytes) {
        byte[] checksum = calculateChecksum(bytes);
        byte[] checksummedBytes = new byte[bytes.length + 4];
        System.arraycopy(bytes, 0, checksummedBytes, 0, bytes.length);
        System.arraycopy(checksum, 0, checksummedBytes, bytes.length, 4);
        return Base58.encode(checksummedBytes);
//        return encode(checksummedBytes);
    }

    /**
     * Calculates a 4-byte checksum for Base58Check encoding.
     *
     * <p>The checksum is the first 4 bytes of the double SHA256 hash of the input data.
     * This provides error detection for encoded data.</p>
     *
     * @param bytes the input bytes to checksum
     * @return the 4-byte checksum
     * @see #encodeChecked(byte[])
     */
    private byte[] calculateChecksum(byte[] bytes) {
        byte[] hash = Sha256Hash.hashTwice(bytes);
        byte[] checksum = new byte[4];
        System.arraycopy(hash, 0, checksum, 0, 4);
        return checksum;
    }

    /**
     * Computes the RIPEMD-160 hash of the input data.
     *
     * <p>RIPEMD-160 is used in Bitcoin for creating addresses from public keys.
     * It produces a 20-byte hash value.</p>
     *
     * @param input the input bytes to hash
     * @return the 20-byte RIPEMD-160 hash
     */
    public static byte[] digestRipeMd160(byte[] input) {
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(input, 0, input.length);
        byte[] ripmemdHash = new byte[20];
        digest.doFinal(ripmemdHash, 0);
        return ripmemdHash;
    }

    /****************************************
     *             SIGNATURES              *
     ****************************************/

    /**
     * Signs a transaction hash using the specified key with optional 2FA.
     *
     * <p>This method creates a digital signature for a transaction hash using either
     * a specific key slot or the BIP32-derived key. The signature can be used to
     * authorize cryptocurrency transactions.</p>
     *
     * <p>Key number values:</p>
     * <ul>
     *   <li>0x00-0xFE - Specific key slot number</li>
     *   <li>0xFF - Use current BIP32-derived key</li>
     * </ul>
     *
     * <p>The method supports optional 2FA challenge-response for additional security.
     * When 2FA is used, the challenge response must be exactly 20 bytes.</p>
     *
     * @param keynbr the key number to use for signing (0xFF for BIP32 key)
     * @param txhash the 32-byte transaction hash to sign
     * @param chalresponse optional 20-byte 2FA challenge response, or null
     * @return the APDU response containing the DER-encoded signature
     * @throws IllegalArgumentException if txhash is not 32 bytes or chalresponse is not 20 bytes
     * @see #cardBip32GetExtendedKey(String, Byte, Integer)
     */
    public APDUResponse cardSignTransactionHash(byte keynbr, byte[] txhash, byte[] chalresponse) {

        byte[] data;
        if (txhash.length != 32) {
            throw new RuntimeException("Wrong txhash length (should be 32)");
        }
        if (chalresponse == null) {
            data = new byte[32];
            System.arraycopy(txhash, 0, data, 0, txhash.length);
        } else if (chalresponse.length == 20) {
            data = new byte[32 + 2 + 20];
            int offset = 0;
            System.arraycopy(txhash, 0, data, offset, txhash.length);
            offset += 32;
            data[offset++] = (byte) 0x80; // 2 middle bytes for 2FA flag
            data[offset++] = (byte) 0x00;
            System.arraycopy(chalresponse, 0, data, offset, chalresponse.length);
        } else {
            throw new RuntimeException("Wrong challenge-response length (should be 20)");
        }
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_SIGN_TRANSACTION_HASH, keynbr, 0x00, data);

        logger.info("SATOCHIPLIB: C-APDU cardSignTransactionHash:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardSignTransactionHash:" + respApdu.toHexString());
        // TODO: check SW code for particular status

        return respApdu;
    }

    // TODO: add Schnorr signatures
    // TODO: add MuSig2 signatures

    /****************************************
     *               2FA commands            *
     ****************************************/


    /****************************************
     *                SATODIME              *
     ****************************************/

    /**
     * Retrieves the current status of the Satodime device.
     *
     * <p>This method queries the Satodime for its current state including:</p>
     * <ul>
     *   <li>Setup completion status</li>
     *   <li>Unlock counter value</li>
     *   <li>Maximum number of key slots</li>
     *   <li>Individual key slot states</li>
     * </ul>
     *
     * <p>The status is automatically cached in the internal satodimeStatus object
     * and can be accessed via {@link #getSatodimeStatus()}.</p>
     *
     * @return the APDU response containing status information
     * @see SatodimeStatus
     * @see #getSatodimeStatus()
     */
    public APDUResponse satodimeGetStatus() {
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_SATODIME_STATUS, 0x00, 0x00, new byte[0]);

        logger.info("SATOCHIPLIB: C-APDU satodimeGetStatus:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU satodimeGetStatus:" + respApdu.toHexString());

        satodimeStatus.updateStatus(respApdu);
        //satodimeStatus= new SatodimeStatus(respApdu);
        //satodimeStatus.setUnlockCounter(satodimeStatus.getUnlockCounter());

        return respApdu;
    }

    /**
     * Retrieves the status of a specific Satodime key slot.
     *
     * <p>This method returns detailed information about a particular key slot including:</p>
     * <ul>
     *   <li>Key status (uninitialized/sealed/unsealed)</li>
     *   <li>Key type and asset information</li>
     *   <li>SLIP-44 coin type</li>
     *   <li>Smart contract details</li>
     *   <li>Token ID information</li>
     *   <li>Additional metadata</li>
     * </ul>
     *
     * @param keyNbr the key slot number to query (0-255)
     * @return the APDU response containing key slot status
     * @see SatodimeKeyslotStatus
     * @see #satodimeGetStatus()
     */
    public APDUResponse satodimeGetKeyslotStatus(int keyNbr) {

        byte keyslot = (byte) (keyNbr % 256);
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_SATODIME_KEYSLOT_STATUS, keyslot, 0x00, new byte[0]);
        logger.info("SATOCHIPLIB: C-APDU satodimeGetKeyslotStatus:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU satodimeGetKeyslotStatus:" + respApdu.toHexString());

        return respApdu;
    }

    /**
     * Sets the metadata for a Satodime key slot (part 0 of 2).
     *
     * <p>This method configures the metadata for a key slot including asset type,
     * SLIP-44 coin type, smart contract address, and token ID. This is the first
     * part of the key slot configuration process.</p>
     *
     * <p>The operation requires owner authentication via unlock code generation.
     * Upon successful completion, the unlock counter is automatically incremented.</p>
     *
     * @param keyNbr the key slot number to configure (0-255)
     * @param RFU1 reserved for future use (set to 0)
     * @param RFU2 reserved for future use (set to 0)
     * @param key_asset the asset type (coin=0x01, token=0x10, NFT=0x40, etc.)
     * @param key_slip44 the 4-byte SLIP-44 coin type identifier
     * @param key_contract the 34-byte smart contract address (TLV format)
     * @param key_tokenid the 34-byte token ID (TLV format)
     * @return the APDU response from the configuration command
     * @throws IllegalArgumentException if any parameter has incorrect length
     * @see #satodimeSetKeyslotStatusPart1(int, byte[])
     * @see Constants#MAP_CODE_BY_ASSET
     */
    public APDUResponse satodimeSetKeyslotStatusPart0(int keyNbr, int RFU1, int RFU2, int key_asset, byte[] key_slip44, byte[] key_contract, byte[] key_tokenid) {

        byte keyslot = (byte) (keyNbr % 256);
        // check inputs
        if (key_slip44.length != SIZE_SLIP44) {
            throw new RuntimeException("Wrong key_slip44 size (should be 4)");
        }
        if (key_contract.length != SIZE_CONTRACT) {
            throw new RuntimeException("Wrong key_contract size (should be 34)");
        }
        if (key_tokenid.length != SIZE_TOKENID) {
            throw new RuntimeException("Wrong key_tokenid size (should be 34)");
        }

        // compute unlock code
        byte[] challenge = new byte[5];
        challenge[0] = CLA;
        challenge[1] = INS_SET_SATODIME_KEYSLOT_STATUS;
        challenge[2] = keyslot;
        challenge[3] = (byte) 0x00;
        challenge[4] = (byte) (SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + 3 + SIZE_SLIP44 + SIZE_CONTRACT + SIZE_TOKENID);
        byte[] unlockCode = satodimeStatus.computeUnlockCode(challenge);
        byte[] data = new byte[unlockCode.length + 3 + SIZE_SLIP44 + SIZE_CONTRACT + SIZE_TOKENID];
        int offset = 0;
        System.arraycopy(unlockCode, 0, data, offset, unlockCode.length);
        offset += unlockCode.length;
        data[offset++] = (byte) RFU1;
        data[offset++] = (byte) RFU2;
        data[offset++] = (byte) key_asset;
        System.arraycopy(key_slip44, 0, data, offset, SIZE_SLIP44);
        offset += SIZE_SLIP44;
        System.arraycopy(key_contract, 0, data, offset, SIZE_CONTRACT);
        offset += SIZE_CONTRACT;
        System.arraycopy(key_tokenid, 0, data, offset, SIZE_TOKENID);
        offset += SIZE_TOKENID;

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_SET_SATODIME_KEYSLOT_STATUS, keyslot, 0x00, data);

        logger.info("SATOCHIPLIB: C-APDU satodimeSetKeyslotStatusPart0:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU satodimeSetKeyslotStatusPart0:" + respApdu.toHexString());
        if (respApdu.isOK()) {
            satodimeStatus.incrementUnlockCounter();
        }
        return respApdu;
    }

    /**
     * Sets the additional data for a Satodime key slot (part 1 of 2).
     *
     * <p>This method completes the key slot configuration by setting additional
     * metadata. This must be called after {@link #satodimeSetKeyslotStatusPart0}
     * to complete the key slot setup process.</p>
     *
     * <p>The operation requires owner authentication and increments the unlock counter
     * upon successful completion.</p>
     *
     * @param keyNbr the key slot number to configure (0-255)
     * @param key_data the 66-byte additional metadata (TLV format)
     * @return the APDU response from the configuration command
     * @throws IllegalArgumentException if key_data is not exactly 66 bytes
     * @see #satodimeSetKeyslotStatusPart0(int, int, int, int, byte[], byte[], byte[])
     */
    public APDUResponse satodimeSetKeyslotStatusPart1(int keyNbr, byte[] key_data) {

        byte keyslot = (byte) (keyNbr % 256);
        // check inputs
        if (key_data.length != SIZE_DATA) {
            throw new RuntimeException("Wrong key_data size (should be 66)");
        }

        // compute unlock code
        byte[] challenge = new byte[5];
        challenge[0] = CLA;
        challenge[1] = INS_SET_SATODIME_KEYSLOT_STATUS;
        challenge[2] = keyslot;
        challenge[3] = (byte) 0x01;
        challenge[4] = (byte) (SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + SIZE_DATA);
        byte[] unlockCode = satodimeStatus.computeUnlockCode(challenge);
        byte[] data = new byte[unlockCode.length + SIZE_DATA];
        int offset = 0;
        System.arraycopy(unlockCode, 0, data, offset, unlockCode.length);
        offset += unlockCode.length;
        System.arraycopy(key_data, 0, data, offset, SIZE_DATA);
        offset += SIZE_DATA;

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_SET_SATODIME_KEYSLOT_STATUS, keyslot, 0x01, data);

        logger.info("SATOCHIPLIB: C-APDU satodimeSetKeyslotStatusPart1:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU satodimeSetKeyslotStatusPart1:" + respApdu.toHexString());
        if (respApdu.isOK()) {
            satodimeStatus.incrementUnlockCounter();
        }
        return respApdu;
    }

    /**
     * Retrieves the public key for a specific Satodime key slot.
     *
     * <p>This method returns the public key associated with a key slot without
     * changing the key's state. The public key can be used to verify ownership
     * and generate addresses without revealing the private key.</p>
     *
     * <p>The returned public key is authenticated with a signature from the
     * device's authentication key to prevent tampering.</p>
     *
     * @param keyNbr the key slot number to query (0-255)
     * @return the APDU response containing the authenticated public key
     * @see #satodimeGetPrivkey(int)
     */
    public APDUResponse satodimeGetPubkey(int keyNbr) {

        byte keyslot = (byte) (keyNbr % 256);
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_SATODIME_PUBKEY, keyslot, 0x00, new byte[0]);

        logger.info("SATOCHIPLIB: C-APDU satodimeGetPubkey:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU satodimeGetPubkey:" + respApdu.toHexString());

        return respApdu;
    }

    /**
     * Retrieves the private key for a specific Satodime key slot.
     *
     * <p>This method returns the private key and entropy data for a key slot without
     * changing the key's state. This operation requires owner authentication via
     * unlock code and increments the unlock counter upon success.</p>
     *
     * <p><strong>Security Warning:</strong> The private key provides full control
     * over associated cryptocurrency assets. Handle with extreme care and ensure
     * secure storage.</p>
     *
     * <p>The response includes:</p>
     * <ul>
     *   <li>Entropy data used to generate the key</li>
     *   <li>32-byte private key</li>
     *   <li>Authentication signature</li>
     * </ul>
     *
     * @param keyNbr the key slot number to query (0-255)
     * @return the APDU response containing the private key and entropy
     * @see #satodimeGetPubkey(int)
     * @see #satodimeUnsealKey(int)
     */
    public APDUResponse satodimeGetPrivkey(int keyNbr) {

        byte keyslot = (byte) (keyNbr % 256);

        // compute unlock code
        byte[] challenge = new byte[5];
        challenge[0] = CLA;
        challenge[1] = INS_GET_SATODIME_PRIVKEY;
        challenge[2] = keyslot;
        challenge[3] = (byte) 0x00;
        challenge[4] = (byte) (SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE);
        byte[] unlockCode = satodimeStatus.computeUnlockCode(challenge);

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_SATODIME_PRIVKEY, keyslot, 0x00, unlockCode);

        logger.info("SATOCHIPLIB: C-APDU satodimeGetPrivkey:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU satodimeGetPrivkey:" + respApdu.getSw());
        if (respApdu.isOK()) {
            satodimeStatus.incrementUnlockCounter();
        }
        return respApdu;
    }

    /**
     * Seals a Satodime key slot with user-provided entropy.
     *
     * <p>This method transitions a key slot from uninitialized to sealed state.
     * When sealed, a key is generated using a combination of user entropy,
     * device entropy, and the authentication key coordinate.</p>
     *
     * <p>The sealing process:</p>
     * <ol>
     *   <li>Combines user entropy with device-generated entropy</li>
     *   <li>Generates a cryptographic key pair</li>
     *   <li>Transitions the slot to sealed state</li>
     *   <li>Increments the unlock counter</li>
     * </ol>
     *
     * <p>Once sealed, the key can be retrieved via {@link #satodimeGetPubkey(int)}
     * but the private key remains protected until unsealing.</p>
     *
     * @param keyNbr the key slot number to seal (0-255)
     * @param entropy_user the 32-byte user-provided entropy for key generation
     * @return the APDU response from the sealing operation
     * @throws IllegalArgumentException if entropy_user is not exactly 32 bytes
     * @see #satodimeUnsealKey(int)
     * @see #satodimeResetKey(int)
     */
    public APDUResponse satodimeSealKey(int keyNbr, byte[] entropy_user) {

        byte keyslot = (byte) (keyNbr % 256);

        // compute unlock code
        byte[] challenge = new byte[5];
        challenge[0] = CLA;
        challenge[1] = INS_SEAL_SATODIME_KEY;
        challenge[2] = keyslot;
        challenge[3] = (byte) 0x00;
        challenge[4] = (byte) (SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + SIZE_ENTROPY);
        byte[] unlockCode = satodimeStatus.computeUnlockCode(challenge);
        byte[] data = new byte[unlockCode.length + entropy_user.length];
        System.arraycopy(unlockCode, 0, data, 0, unlockCode.length);
        System.arraycopy(entropy_user, 0, data, unlockCode.length, entropy_user.length);

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_SEAL_SATODIME_KEY, keyslot, 0x00, data);

        logger.info("SATOCHIPLIB: C-APDU satodimeSealKey:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU satodimeSealKey:" + respApdu.toHexString());
        if (respApdu.isOK()) {
            satodimeStatus.incrementUnlockCounter();
        }
        return respApdu;
    }

    /**
     * Unseals a Satodime key slot, making the private key accessible.
     *
     * <p>This method transitions a key slot from sealed to unsealed state, making
     * the private key accessible via {@link #satodimeGetPrivkey(int)}. This is
     * typically the final step before spending associated cryptocurrency assets.</p>
     *
     * <p><strong>Security Implications:</strong> Once unsealed, the private key
     * becomes accessible and the bearer bond value can be claimed. This operation
     * should only be performed when ready to transfer ownership or spend assets.</p>
     *
     * <p>The operation requires owner authentication and increments the unlock counter.</p>
     *
     * @param keyNbr the key slot number to unseal (0-255)
     * @return the APDU response from the unsealing operation
     * @see #satodimeSealKey(int, byte[])
     * @see #satodimeGetPrivkey(int)
     */
    public APDUResponse satodimeUnsealKey(int keyNbr) {

        byte keyslot = (byte) (keyNbr % 256);

        // compute unlock code
        byte[] challenge = new byte[5];
        challenge[0] = CLA;
        challenge[1] = INS_UNSEAL_SATODIME_KEY;
        challenge[2] = keyslot;
        challenge[3] = (byte) 0x00;
        challenge[4] = (byte) (SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE);
        byte[] unlockCode = satodimeStatus.computeUnlockCode(challenge);

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_UNSEAL_SATODIME_KEY, keyslot, 0x00, unlockCode);

        logger.info("SATOCHIPLIB: C-APDU satodimeUnsealKey:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU satodimeUnsealKey:" + respApdu.toHexString());
        if (respApdu.isOK()) {
            satodimeStatus.incrementUnlockCounter();
        }
        return respApdu;
    }

    /**
     * Resets a Satodime key slot to uninitialized state.
     *
     * <p>This method transitions a key slot from unsealed back to uninitialized state,
     * effectively erasing the key and allowing the slot to be reused with new entropy.
     * This operation can only be performed on unsealed key slots.</p>
     *
     * <p>Use cases for key reset:</p>
     * <ul>
     *   <li>Preparing a slot for new assets after spending</li>
     *   <li>Correcting metadata errors</li>
     *   <li>Reusing slots in testing scenarios</li>
     * </ul>
     *
     * <p>The operation requires owner authentication and increments the unlock counter.</p>
     *
     * @param keyNbr the key slot number to reset (0-255)
     * @return the APDU response from the reset operation
     * @see #satodimeSealKey(int, byte[])
     * @see #satodimeUnsealKey(int)
     */
    public APDUResponse satodimeResetKey(int keyNbr) {

        byte keyslot = (byte) (keyNbr % 256);

        // compute unlock code
        byte[] challenge = new byte[5];
        challenge[0] = CLA;
        challenge[1] = INS_RESET_SATODIME_KEY;
        challenge[2] = keyslot;
        challenge[3] = (byte) 0x00;
        challenge[4] = (byte) (SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE);
        byte[] unlockCode = satodimeStatus.computeUnlockCode(challenge);

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_RESET_SATODIME_KEY, keyslot, 0x00, unlockCode);

        logger.info("SATOCHIPLIB: C-APDU satodimeResetKey:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU satodimeResetKey:" + respApdu.toHexString());
        if (respApdu.isOK()) {
            satodimeStatus.incrementUnlockCounter();
        }
        return respApdu;
    }

    /**
     * Initiates ownership transfer of the Satodime device.
     *
     * <p>This method prepares the Satodime for transfer to a new owner by generating
     * new unlock credentials. After this operation, the current unlock secret becomes
     * invalid and a new unlock secret is established.</p>
     *
     * <p>Transfer process:</p>
     * <ol>
     *   <li>Current owner calls this method with valid unlock code</li>
     *   <li>Device generates new unlock secret</li>
     *   <li>Old unlock secret becomes invalid</li>
     *   <li>New owner receives device with new unlock secret</li>
     * </ol>
     *
     * <p><strong>Important:</strong> After calling this method, the current unlock
     * secret will no longer work. Ensure the new unlock secret is properly
     * communicated to the new owner.</p>
     *
     * @return the APDU response containing new ownership credentials
     * @see #setSatodimeUnlockSecret(byte[])
     * @see #getSatodimeUnlockSecret()
     */
    public APDUResponse satodimeInitiateOwnershipTransfer() {

        // compute unlock code
        byte[] challenge = new byte[5];
        challenge[0] = CLA;
        challenge[1] = INS_INITIATE_SATODIME_TRANSFER;
        challenge[2] = (byte) 0x00;
        challenge[3] = (byte) 0x00;
        challenge[4] = (byte) (SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE);
        byte[] unlockCode = satodimeStatus.computeUnlockCode(challenge);

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_INITIATE_SATODIME_TRANSFER, 0x00, 0x00, unlockCode);

        logger.info("SATOCHIPLIB: C-APDU satodimeInitiateOwnershipTransfer:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU satodimeInitiateOwnershipTransfer:" + respApdu.toHexString());
        if (respApdu.isOK()) {
            satodimeStatus.incrementUnlockCounter();
        }
        return respApdu;
    }

    /****************************************
     *            SEEDKEEPER                *
     ****************************************/

    /**
     * Retrieves the current status of the SeedKeeper applet.
     *
     * <p>This method queries the SeedKeeper for its operational status including:</p>
     * <ul>
     *   <li>Number of stored secrets</li>
     *   <li>Total and available memory</li>
     *   <li>Log information (total and available entries)</li>
     *   <li>Setup completion status</li>
     * </ul>
     *
     * <p>The status information is essential for managing secret storage capacity
     * and monitoring device usage.</p>
     *
     * @return the SeedKeeper status object containing current state information
     * @see SeedkeeperStatus
     * @throws RuntimeException if the SeedKeeper is not properly initialized
     */
    public SeedkeeperStatus seedkeeperGetStatus() {
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_SEEDKEEPER_STATUS, 0x00, 0x00, new byte[0]);

        logger.info("SATOCHIPLIB: C-APDU seedkeeperGetStatus:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU seedkeeperGetStatus:" + respApdu.toHexString());
        SeedkeeperStatus seedkeeperStatus = new SeedkeeperStatus();
        seedkeeperStatus.updateStatus(respApdu);

        return seedkeeperStatus;
    }

    /**
     * Generates a random master seed within the SeedKeeper.
     *
     * <p><strong>Deprecated:</strong> This method is only for SeedKeeper v0.1.
     * For SeedKeeper v0.2 and later, use {@link #seedkeeperGenerateRandomSecret}
     * which provides more flexibility and security options.</p>
     *
     * <p>This method generates a cryptographically secure random master seed
     * directly on the device, ensuring the seed never exists in plaintext outside
     * the secure element.</p>
     *
     * @param seedSize the seed size in bytes (16-64 bytes)
     * @param exportRights the export rights policy for the generated secret
     * @param label a human-readable label for the secret
     * @return the secret header containing metadata about the generated seed
     * @throws Exception if seed generation fails or parameters are invalid
     * @see #seedkeeperGenerateRandomSecret
     * @see SeedkeeperExportRights
     * @deprecated Use seedkeeperGenerateRandomSecret for SeedKeeper v0.2+
     */
    public SeedkeeperSecretHeader seedkeeperGenerateMasterseed(int seedSize, SeedkeeperExportRights exportRights, String label) throws Exception {
        byte[] labelBytes = label.getBytes(StandardCharsets.UTF_8);
        byte[] data = new byte[labelBytes.length + 1];
        data[0] = (byte) labelBytes.length;
        System.arraycopy(labelBytes, 0, data, 1, labelBytes.length);

        APDUCommand plainApdu = new APDUCommand(
                0xB0,
                INS_GENERATE_SEEDKEEPER_MASTER_SEED,
                seedSize,
                exportRights.ordinal(),
                data
        );
        logger.info("SATOCHIPLIB: C-APDU seedkeeperGenerateMasterseed:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU seedkeeperGenerateMasterseed:" + respApdu.toHexString());

        respApdu.checkOK();
        byte[] response = respApdu.getData();
        int responseLength = response.length;
        int expectedLength = 6;

        if (responseLength < expectedLength) {
            throw new RuntimeException("Wrong response length: " + responseLength + ", expected: " + expectedLength);
        }

        int sid = 256 * (response[0] & 0xFF) + (response[1] & 0xFF);
        byte[] fingerprintBytes = Arrays.copyOfRange(response, 2, 6);
        SeedkeeperSecretHeader header = new SeedkeeperSecretHeader(
                sid,
                SeedkeeperSecretType.MASTERSEED,
                (byte) 0,
                SeedkeeperSecretOrigin.GENERATED_ON_CARD,
                exportRights,
                (byte) 0,
                (byte) 0,
                (byte) 0,
                fingerprintBytes,
                label
        );

        return header;
    }

    /**
     * Generates a random secret of specified type within the SeedKeeper.
     *
     * <p>This method creates cryptographically secure random secrets directly on the
     * device with flexible type and security options. The secret never exists in
     * plaintext outside the secure element during generation.</p>
     *
     * <p>Supported secret types include:</p>
     * <ul>
     *   <li>Master seeds for wallet derivation</li>
     *   <li>BIP39 mnemonics</li>
     *   <li>Private keys</li>
     *   <li>Encryption keys</li>
     *   <li>Passwords and other data</li>
     * </ul>
     *
     * <p>Optional entropy can be provided to contribute to the randomness,
     * and if saveEntropy is true, the entropy will be stored as a separate secret.</p>
     *
     * @param stype the type of secret to generate
     * @param subtype subtype classification for the secret
     * @param size the size of the secret in bytes (16-64)
     * @param saveEntropy whether to save the provided entropy as a separate secret
     * @param entropy additional entropy bytes to mix into generation
     * @param exportRights the export rights policy for the generated secret
     * @param label a human-readable label for the secret
     * @return list of secret headers (main secret and optionally entropy secret)
     * @throws Exception if generation fails or parameters are invalid
     * @see SeedkeeperSecretType
     * @see SeedkeeperExportRights
     */
    public List<SeedkeeperSecretHeader> seedkeeperGenerateRandomSecret(
            SeedkeeperSecretType stype,
            byte subtype,
            byte size,
            boolean saveEntropy,
            byte[] entropy,
            SeedkeeperExportRights exportRights,
            String label
    ) throws Exception {

        if (size < 16 || size > 64) {
            throw new RuntimeException("Wrong secret size size:" + size);
        }

        byte[] labelBytes = label.getBytes(StandardCharsets.UTF_8);
        byte[] saveEntropyByte = new byte[]{saveEntropy ? (byte) 0x01 : (byte) 0x00};
        byte[] data = new byte[3 + labelBytes.length + 1 + entropy.length + 1];

        data[0] = stype.getValue(); // Assuming getValue() returns the byte value
        data[1] = subtype;
        data[2] = saveEntropyByte[0];
        data[3] = (byte) labelBytes.length;
        System.arraycopy(labelBytes, 0, data, 4, labelBytes.length);
        data[4 + labelBytes.length] = (byte) entropy.length;
        System.arraycopy(entropy, 0, data, 5 + labelBytes.length, entropy.length);

        APDUCommand plainApdu = new APDUCommand(
                0xB0, // Assuming getValue() returns the byte value
                INS_GENERATE_SEEDKEEPER_RANDOM_SECRET, // Assuming getValue() returns the byte value
                size,
                exportRights.getValue(), // Assuming getValue() returns the byte value
                data
        );

        logger.info("SATOCHIPLIB: C-APDU seedkeeperGenerateRandomSecret:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU seedkeeperGenerateRandomSecret:" + respApdu.toHexString());

        respApdu.checkOK();
        byte[] response = respApdu.getData();
        int responseLength = response.length;
        int expectedLength = saveEntropy ? 12 : 6;

        if (responseLength < expectedLength) {
            throw new Exception("Wrong response length: " + responseLength + ", expected: " + expectedLength);
        }

        int sid = 256 * (response[0] & 0xFF) + (response[1] & 0xFF);
        byte[] fingerprintBytes = Arrays.copyOfRange(response, 2, 6);

        SeedkeeperSecretHeader header = new SeedkeeperSecretHeader(
                sid,
                stype,
                subtype,
                SeedkeeperSecretOrigin.GENERATED_ON_CARD,
                exportRights,
                (byte) 0,
                (byte) 0,
                (byte) 0,
                fingerprintBytes,
                label
        );

        List<SeedkeeperSecretHeader> headers = new ArrayList<>();
        headers.add(header);

        if (responseLength >= 12) {
            int sid2 = 256 * (response[6] & 0xFF) + (response[7] & 0xFF);
            byte[] fingerprint2Bytes = Arrays.copyOfRange(response, 8, 12);

            SeedkeeperSecretHeader header2 = new SeedkeeperSecretHeader(
                    sid2,
                    SeedkeeperSecretType.KEY,
                    (byte) 0x10, // Assuming getValue() returns the byte value
                    SeedkeeperSecretOrigin.GENERATED_ON_CARD,
                    exportRights,
                    (byte) 0,
                    (byte) 0,
                    (byte) 0,
                    fingerprint2Bytes,
                    "entropy"
            );
            headers.add(header2);
        }

        return headers;
    }

    /**
     * Imports a secret into the SeedKeeper with optional encryption.
     *
     * <p>This method allows importing external secrets into the SeedKeeper with
     * support for both plaintext and encrypted import. For large secrets, the
     * data is transmitted in chunks to accommodate APDU size limitations.</p>
     *
     * <p>Import modes:</p>
     * <ul>
     *   <li>Plaintext import - secret transmitted in clear (secure channel protection)</li>
     *   <li>Encrypted import - secret pre-encrypted with device public key</li>
     * </ul>
     *
     * <p>The import process includes integrity verification through fingerprint
     * comparison to ensure data was transmitted correctly.</p>
     *
     * @param secretObject the secret object containing data, metadata, and optional encryption parameters
     * @return the secret header with assigned secret ID
     * @throws Exception if import fails, data is corrupted, or fingerprints don't match
     * @see SeedkeeperSecretObject
     * @see #seedkeeperExportSecret(int, Integer)
     */
    public SeedkeeperSecretHeader seedkeeperImportSecret(
            SeedkeeperSecretObject secretObject
    ) throws Exception {
        logger.info("SATOCHIPLIB: seedkeeperImportSecret");
        SeedkeeperSecretHeader secretHeader = secretObject.getSecretHeader();
        Integer sidPubKey = (secretObject.getSecretEncryptedParams() != null) ? secretObject.getSecretEncryptedParams().getSidPubkey() : null;
        boolean isSecureExport = sidPubKey != null;
        byte[] secretBytes = secretObject.getSecretBytes();
        int secretPaddedSize = 0;
        if (isSecureExport) {
            secretPaddedSize = secretBytes.length;
        } else {
            int secretSize = secretBytes.length;
            int padSize = 16 - (secretSize) % 16;
            secretPaddedSize = secretSize + padSize;
        }

        List<Byte> dataArray = new ArrayList<>();
        for (byte i : secretHeader.getHeaderBytes()) {
            dataArray.add(i);
        }

        if (isSecureExport) {
            dataArray.add((byte) (sidPubKey >> 8));
            dataArray.add((byte) (sidPubKey & 0xFF));
            if (secretObject.getSecretEncryptedParams() != null) {
                for (byte i : secretObject.getSecretEncryptedParams().getIv()) {
                    dataArray.add(i);
                }
            }
        }
        dataArray.add((byte) ((secretPaddedSize >> 8) & 0xFF));
        dataArray.add((byte) (secretPaddedSize & 0xFF));


        byte[] data = new byte[dataArray.size()];
        for (int i = 0; i < dataArray.size(); i++) {
            data[i] = dataArray.get(i);
        }

        APDUCommand plainApdu = new APDUCommand(
                0xB0,
                INS_IMPORT_SEEDKEEPER_SECRET,
                isSecureExport ? (byte) 0x02 : (byte) 0x01,
                (byte) 0x01,
                data
        );

        logger.warning("SATOCHIPLIB: C-APDU seedkeeperImportSecret before loop:" + plainApdu.toHexString());
        APDUResponse respApdu = cardTransmit(plainApdu);
        logger.warning("SATOCHIPLIB: R-APDU seedkeeperImportSecret before loop:" + respApdu.toHexString());

        respApdu.checkOK();
        // repeat process
        int chunkSize = 128;
        int secretOffset = 0;
        int secretRemaining = secretBytes.length;

        while (secretRemaining > chunkSize) {
            byte[] chunk = new byte[chunkSize + 2];
            chunk[0] = (byte) (chunkSize >> 8);
            chunk[1] = (byte) (chunkSize & 0xFF);
            System.arraycopy(secretBytes, secretOffset, chunk, 2, chunkSize);
            plainApdu = new APDUCommand(
                    0xB0,
                    INS_IMPORT_SEEDKEEPER_SECRET,
                    isSecureExport ? (byte) 0x02 : (byte) 0x01,
                    (byte) 0x02,
                    chunk
            );

            //logger.warning("SATOCHIPLIB: C-APDU seedkeeperImportSecret:" + plainApdu.toHexString());
            logger.warning("SATOCHIPLIB: C-APDU seedkeeperImportSecret");
            respApdu = this.cardTransmit(plainApdu);
            logger.warning("SATOCHIPLIB: R-APDU seedkeeperImportSecret:" + respApdu.toHexString());
            respApdu.checkOK();
            secretOffset += chunkSize;
            secretRemaining -= chunkSize;
        }

        byte[] chunk = new byte[secretRemaining + 2];
        chunk[0] = (byte) (secretRemaining >> 8);
        chunk[1] = (byte) (secretRemaining & 0xFF);
        System.arraycopy(secretBytes, secretOffset, chunk, 2, secretRemaining);
        if(isSecureExport && secretObject.getSecretEncryptedParams() != null) {
            byte[] hmacBytes = secretObject.getSecretEncryptedParams().getHmac();
            byte[] hmacChunk = new byte[chunk.length + 1 + hmacBytes.length];
            System.arraycopy(chunk, 0, hmacChunk, 0, chunk.length);
            hmacChunk[chunk.length] = (byte) hmacBytes.length;
            System.arraycopy(hmacBytes, 0, hmacChunk, chunk.length + 1, hmacBytes.length);
            chunk = hmacChunk;
        }

        plainApdu = new APDUCommand(
                0xB0,
                INS_IMPORT_SEEDKEEPER_SECRET,
                isSecureExport ? (byte) 0x02 : (byte) 0x01,
                (byte) 0x03,
                chunk
        );

        //logger.warning("SATOCHIPLIB: C-APDU seedkeeperImportSecret:" + plainApdu.toHexString());
        logger.warning("SATOCHIPLIB: C-APDU seedkeeperImportSecret");
        respApdu = this.cardTransmit(plainApdu);
        logger.warning("SATOCHIPLIB: R-APDU seedkeeperImportSecret:" + respApdu.toHexString());
        respApdu.checkOK();

        secretOffset += secretRemaining;
        secretRemaining -= 0;

        byte[] response = respApdu.getData();
        int responseLength = response.length;

        if (responseLength < 6) {
            throw new RuntimeException("Wrong response length: " + responseLength);
        }

        int sid = 256 * (response[0] & 0xFF) + (response[1] & 0xFF);

        byte[] fingerprintFromSeedkeeper = Arrays.copyOfRange(response, 2, 6);
        byte[] fingerprintFromSecret = secretObject.getFingerprintFromSecret();

        if(Arrays.equals(fingerprintFromSecret, fingerprintFromSeedkeeper)) {
            logger.warning("SATOCHIPLIB: seedkeeperImportSecret: Fingerprints match!");
        } else {
            logger.warning("SATOCHIPLIB: seedkeeperImportSecret: Fingerprints mismatch:" +
                    " expected" + Arrays.toString(fingerprintFromSecret) +
                    "but recovered" +
                    Arrays.toString(fingerprintFromSeedkeeper)
            );
            throw new RuntimeException("Fingerprints mismatch: " +
                    " expected" + Arrays.toString(fingerprintFromSecret) +
                    "but recovered" +
                    Arrays.toString(fingerprintFromSeedkeeper)
            );
        }
        secretHeader.sid = sid;
        return secretHeader;
    }

    /**
     * Exports a secret from the SeedKeeper with optional encryption.
     *
     * <p>This method retrieves a stored secret from the SeedKeeper. The secret can be
     * exported in plaintext (protected by secure channel) or encrypted with a public key
     * for secure transfer between devices.</p>
     *
     * <p>Export modes:</p>
     * <ul>
     *   <li>Plaintext export (sidPubKey = null) - secret returned in clear over secure channel</li>
     *   <li>Encrypted export (sidPubKey provided) - secret encrypted with specified public key</li>
     * </ul>
     *
     * <p>For large secrets, the data is retrieved in chunks. The method includes integrity
     * verification for plaintext exports to ensure data correctness.</p>
     *
     * @param sid the secret ID to export
     * @param sidPubKey optional secret ID of public key for encryption, or null for plaintext
     * @return the secret object containing data, metadata, and encryption parameters
     * @throws Exception if export fails, secret not found, or export not permitted
     * @see #seedkeeperImportSecret(SeedkeeperSecretObject)
     * @see SeedkeeperExportRights
     */
    public SeedkeeperSecretObject seedkeeperExportSecret(
            int sid,
            Integer sidPubKey
    ) throws Exception {
        logger.info("SATOCHIPLIB: seedkeeperExportSecret");
        boolean isSecureExport = sidPubKey != null;
        List<Byte> dataArray = new ArrayList<>();
        dataArray.add((byte) (sid >> 8));
        dataArray.add((byte) (sid & 0xFF));
        if (sidPubKey != null) {
            dataArray.add((byte) (sidPubKey >> 8));
            dataArray.add((byte) (sidPubKey & 0xFF));
        }

        // Convert List<Byte> to byte[]
        byte[] data = new byte[dataArray.size()];
        for (int i = 0; i < dataArray.size(); i++) {
            data[i] = dataArray.get(i);
        }

        APDUCommand plainApdu = new APDUCommand(
                0xB0,
                INS_EXPORT_SEEDKEEPER_SECRET,
                isSecureExport ? (byte) 0x02 : (byte) 0x01,
                (byte) 0x01,
                data
        );

        logger.info("SATOCHIPLIB: C-APDU seedkeeperExportSecret:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU seedkeeperExportSecret:" + respApdu.toHexString());

        respApdu.checkOK();

        byte[] response = respApdu.getData();
        SeedkeeperSecretHeader header = new SeedkeeperSecretHeader(response);

        byte[] iv = new byte[0];
        if (isSecureExport) {
            iv = new byte[16];
            System.arraycopy(response, response.length - 16, iv, 0, 16);
        }

        // OP_PROCESS
        List<Byte> secretBytes = new ArrayList<>();
        int sigSize = 0;
        List<Byte> sigBytes = new ArrayList<>();
        while (true) {
            plainApdu = new APDUCommand(
                    0xB0,
                    INS_EXPORT_SEEDKEEPER_SECRET,
                    isSecureExport ? (byte) 0x02 : (byte) 0x01,
                    (byte) 0x02,
                    new byte[0]
            );
            //logger.info("SATOCHIPLIB: C-APDU seedkeeperExportSecret:" + plainApdu.toHexString());
            logger.info("SATOCHIPLIB: C-APDU seedkeeperExportSecret:" + plainApdu.toHexString());
            respApdu = this.cardTransmit(plainApdu);
            logger.info("SATOCHIPLIB: R-APDU seedkeeperExportSecret");
            respApdu.checkOK();


            // parse response
            response = respApdu.getData();
            int responseSize = response.length;
            int chunkSize = 256 * (response[0] & 0xFF) + (response[1] & 0xFF);
            for (int i = 2; i < 2 + chunkSize; i++) {
                secretBytes.add(response[i]);
            }

            // check if last chunk
            if (chunkSize + 2 < responseSize) {
                int offset = chunkSize + 2;
                sigSize = 256 * (response[offset] & 0xFF) + (response[offset + 1] & 0xFF);
                offset += 2;
                for (int i = offset; i < offset + sigSize; i++) {
                    sigBytes.add(response[i]);
                }
                break;
            }
        }
        // create secretObject
        byte[] sigByteArray = new byte[sigBytes.size()];
        for (int i = 0; i < sigBytes.size(); i++) {
            sigByteArray[i] = sigBytes.get(i);
        }
        SeedkeeperSecretEncryptedParams secretEncryptedParams = isSecureExport ? new SeedkeeperSecretEncryptedParams(sidPubKey, iv, sigByteArray) : null;
        byte[] secretBytesArray = new byte[secretBytes.size()];
        for (int i = 0; i < secretBytes.size(); i++) {
            secretBytesArray[i] = secretBytes.get(i);
        }
        SeedkeeperSecretObject secretObject = new SeedkeeperSecretObject(secretBytesArray, header, isSecureExport, secretEncryptedParams);

        // check fingerprint (only possible for plaintext export)
        if (!isSecureExport) {
            byte[] fingerprintFromSeedkeeper = header.fingerprintBytes;
            byte[] fingerprintFromSecret = secretObject.getFingerprintFromSecret();

            if (Arrays.equals(fingerprintFromSecret, fingerprintFromSeedkeeper)) {
                System.out.println("SATOCHIPLIB seedkeeperExportSecret: Fingerprints match!");
            } else {
                System.out.println("SATOCHIPLIB seedkeeperExportSecret: Fingerprint mismatch: expected " +
                        Arrays.toString(fingerprintFromSecret) + " but recovered " +
                        Arrays.toString(fingerprintFromSeedkeeper));
            }
        }

        return secretObject;
    }

    /**
     * Exports a secret from SeedKeeper encrypted for import into Satochip.
     *
     * <p>This specialized export method prepares a secret for secure transfer to a
     * Satochip device. The secret is encrypted using the Satochip's public key and
     * includes all necessary parameters for import.</p>
     *
     * <p>The exported data includes:</p>
     * <ul>
     *   <li>Secret header with metadata</li>
     *   <li>Initialization vector (IV) for encryption</li>
     *   <li>Encrypted secret data</li>
     *   <li>HMAC for authenticity verification</li>
     * </ul>
     *
     * <p>This method is typically used for migrating secrets between SeedKeeper
     * and Satochip devices securely.</p>
     *
     * @param sid the secret ID to export from SeedKeeper
     * @param sidPubKey the secret ID of the Satochip's trusted public key
     * @return the encrypted secret object ready for Satochip import
     * @throws Exception if export fails or encryption parameters are invalid
     * @see #seedkeeperExportSecret(int, Integer)
     */
    public SeedkeeperSecretObject seedkeeperExportSecretToSatochip(
            int sid,
            Integer sidPubKey
    ) throws Exception {
        logger.info("SATOCHIPLIB: seedkeeperExportSecretToSatochip");
        byte[] data = new byte[] {
                (byte) (sid >> 8), (byte) (sid % 256),
                (byte) (sidPubKey >> 8), (byte) (sidPubKey % 256)
        };

        APDUCommand plainApdu = new APDUCommand(
                0xB0,
                INS_EXPORT_SEEDKEEPER_SECRET_TO_SATOCHIP,
                (byte) 0x00,
                (byte) 0x00,
                data
        );

        logger.info("SATOCHIPLIB: C-APDU seedkeeperExportSecret:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU seedkeeperExportSecret:" + respApdu.toHexString());

        respApdu.checkOK();

        // return: [ id(2b) | header(13b) | IV(16b) | encrypted_secret_size(2b) | encrypted_secret | hmac_size(2b) | hmac(20b) ]
        // parse header
        byte[] response = respApdu.getData();
        SeedkeeperSecretHeader secretHeader = new SeedkeeperSecretHeader(response);

        int offset = 15;
        byte[] iv = Arrays.copyOfRange(response, offset, offset + 16);
        offset += 16;

        int secretSize = (response[offset] & 0xFF) * 256 + (response[offset + 1] & 0xFF);
        offset += 2;

        byte[] secretBytes = Arrays.copyOfRange(response, offset, offset + secretSize);
        offset += secretSize;

        int hmacSize = (response[offset] & 0xFF) * 256 + (response[offset + 1] & 0xFF);
        offset += 2;

        byte[] hmacBytes = Arrays.copyOfRange(response, offset, offset + hmacSize);

        // secretObject
        SeedkeeperSecretEncryptedParams secretParams = new SeedkeeperSecretEncryptedParams(sidPubKey, iv, hmacBytes);
        logger.info("SATOCHIPLIB: seedkeeperExportSecret secretParams:" + secretParams);


        return new SeedkeeperSecretObject(secretBytes, secretHeader, true, secretParams);
    }

    /**
     * Permanently deletes a secret from the SeedKeeper.
     *
     * <p>This method removes a secret and all its associated metadata from the
     * SeedKeeper storage. The operation is irreversible and frees up storage
     * space for new secrets.</p>
     *
     * <p><strong>Warning:</strong> This operation permanently destroys the secret.
     * Ensure the secret is properly backed up if recovery might be needed.</p>
     *
     * <p>Use cases for secret reset:</p>
     * <ul>
     *   <li>Removing obsolete or unused secrets</li>
     *   <li>Cleaning up storage space</li>
     *   <li>Removing compromised secrets</li>
     *   <li>Managing secret lifecycle</li>
     * </ul>
     *
     * <p><strong>Compatibility:</strong> Seedkeeper v0.2 and higher.</p>
     *
     * @param sid the secret ID to delete
     * @return the APDU response confirming deletion
     * @throws APDUException if deletion fails or secret doesn't exist
     * @see #seedkeeperListSecretHeaders()
     */
    public APDUResponse seedkeeperResetSecret(int sid) throws APDUException {
        logger.info("SATOCHIPLIB: seedkeeperResetSecret");

        byte[] data = new byte[]{
                (byte) (sid >> 8), (byte) (sid % 256)
        };
        APDUCommand plainApdu = new APDUCommand(
                0xB0,
                INS_RESET_SEEDKEEPER_SECRET,
                (byte) 0x00,
                (byte) 0x00,
                data
        );
        logger.info("SATOCHIPLIB: C-APDU seedkeeperResetSecret:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU seedkeeperResetSecret:" + respApdu.toHexString());

        respApdu.checkOK();

        return respApdu;
    }

    /**
     * Retrieves a list of all secret headers stored in the SeedKeeper.
     *
     * <p>This method returns metadata about all secrets without revealing the actual
     * secret data. The headers include information such as:</p>
     * <ul>
     *   <li>Secret ID and type</li>
     *   <li>Creation date and origin</li>
     *   <li>Export rights and usage counters</li>
     *   <li>Fingerprint for integrity verification</li>
     *   <li>Human-readable labels</li>
     * </ul>
     *
     * <p>This method is useful for:</p>
     * <ul>
     *   <li>Inventory management of stored secrets</li>
     *   <li>Displaying secret lists to users</li>
     *   <li>Checking available storage space</li>
     *   <li>Auditing secret usage</li>
     * </ul>
     *
     * @return list of secret headers for all stored secrets
     * @throws Exception if retrieval fails or SeedKeeper is not initialized
     * @see SeedkeeperSecretHeader
     * @see #seedkeeperGetStatus()
     */
    public List<SeedkeeperSecretHeader> seedkeeperListSecretHeaders() throws Exception {
        logger.info("SATOCHIPLIB: seedkeeperListSecretHeaders");

        List<SeedkeeperSecretHeader> secretHeaders = new ArrayList<>();
        byte[] data = new byte[]{};
        APDUCommand plainApdu = new APDUCommand(
                0xB0,
                INS_LIST_SEEDKEEPER_SECRET_HEADERS,
                (byte) 0x00,
                (byte) 0x01,
                data
        );
        logger.info("SATOCHIPLIB: C-APDU seedkeeperResetSecret:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU seedkeeperResetSecret:" + respApdu.toHexString());

        // return early for empty cards
        if (respApdu.getSw1() == 0x9C && respApdu.getSw2() == 0x12){
            return secretHeaders;
        }

        respApdu.checkOK();

        while(respApdu.getSw1() == 0x90 && respApdu.getSw2() == 0x00) {
            byte[] response = respApdu.getData();
            SeedkeeperSecretHeader secretHeader = new SeedkeeperSecretHeader(response);
            secretHeaders.add(secretHeader);
            plainApdu = new APDUCommand(
                    0xB0,
                    INS_LIST_SEEDKEEPER_SECRET_HEADERS,
                    (byte) 0x00,
                    (byte) 0x02,
                    data
            );
            logger.info("SATOCHIPLIB: C-APDU seedkeeperResetSecret:" + plainApdu.toHexString());
            respApdu = this.cardTransmit(plainApdu);
            logger.info("SATOCHIPLIB: R-APDU seedkeeperResetSecret:" + respApdu.toHexString());

        }

        return secretHeaders;
    }

    /**
     * Retrieves operation logs from the SeedKeeper for auditing purposes.
     *
     * <p>This method returns a list of logged operations performed on the SeedKeeper.
     * Logs provide an audit trail of device usage and can help with security monitoring
     * and troubleshooting.</p>
     *
     * <p>Log entries typically include:</p>
     * <ul>
     *   <li>Operation type (import, export, generate, etc.)</li>
     *   <li>Secret IDs involved</li>
     *   <li>Operation status/result</li>
     *   <li>Timestamp information</li>
     * </ul>
     *
     * <p>The method can retrieve either just the latest log entry or all available
     * log entries depending on the printAll parameter.</p>
     *
     * @param printAll if true, retrieve all available logs; if false, retrieve only the latest
     * @return list of log entries from the SeedKeeper
     * @throws Exception if log retrieval fails or SeedKeeper is not initialized
     * @see SeedkeeperLog
     * @see #seedkeeperGetStatus()
     */
    public List<SeedkeeperLog> seedkeeperPrintLogs(Boolean printAll) throws Exception {
        boolean isPrintingAll = (printAll != null) ? printAll : true;
        byte[] data = new byte[]{};
        APDUCommand plainApdu = new APDUCommand(
                0xB0,
                INS_PRINT_SEEDKEEPER_LOGS,
                (byte) 0x00,
                (byte) 0x01,
                data
        );
        logger.info("SATOCHIPLIB: C-APDU seedkeeperResetSecret:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU seedkeeperResetSecret:" + respApdu.toHexString());

        respApdu.checkOK();
        byte[] response = respApdu.getData();
        // first log
        List<SeedkeeperLog> logs = new ArrayList<>();
        SeedkeeperLog log;
        int nbTotalLogs = 0;
        int nbAvailLogs = 0;
        if (respApdu.getSw1() == 0x90 && respApdu.getSw2() == 0x00) {
            nbTotalLogs = (response[0] & 0xFF) * 256 + (response[1] & 0xFF);
            nbAvailLogs = (response[2] & 0xFF) * 256 + (response[3] & 0xFF);
            System.out.println("[SatocardCommandSet.seedkeeperPrintLogs] nbTotalLogs: " + nbTotalLogs);
            System.out.println("[SatocardCommandSet.seedkeeperPrintLogs] nbAvailLogs: " + nbAvailLogs);
            if (response.length >= 4 + SeedkeeperLog.LOG_SIZE) {
                log = new SeedkeeperLog(Arrays.copyOfRange(response, 4, 4 + SeedkeeperLog.LOG_SIZE));
                logs.add(log);
                System.out.println("[SatocardCommandSet.seedkeeperPrintLogs] latest log: " + log);
            } else {
                System.out.println("No logs available!");
            }
        } else if (respApdu.getSw1() == 0x9C && respApdu.getSw2() == 0x04) {
            logger.warning("[SatocardCommandSet.seedkeeperPrintLogs] no logs: Seedkeeper is" +
                    " not initialized!");
        } else {
            logger.warning("[SatocardCommandSet.seedkeeperPrintLogs] unexpected error during" +
                    " object listing (code " + respApdu.getSw() + ")");
        }

        // next logs
        int counter = 0;
        while (printAll && respApdu.getSw1() == 0x90 && respApdu.getSw2() == 0x00) {
            plainApdu = new APDUCommand(
                    0xB0,
                    INS_PRINT_SEEDKEEPER_LOGS,
                    (byte) 0x00,
                    (byte) 0x02,
                    data
            );
            logger.info("SATOCHIPLIB: C-APDU seedkeeperResetSecret:" + plainApdu.toHexString());
            respApdu = this.cardTransmit(plainApdu);
            logger.info("SATOCHIPLIB: R-APDU seedkeeperResetSecret:" + respApdu.toHexString());
            response = respApdu.getData();
            if (respApdu.getSw1() != 0x90 || respApdu.getSw2() != 0x00) {
                logger.warning("[SatocardCommandSet.seedkeeperPrintLogs] Error during log printing: (code " + respApdu.getSw() + ")");
                break;
            }
            if (response.length == 0) {
                break;
            }
            // parse response (can contain multiple logs)
            while (response.length >= SeedkeeperLog.LOG_SIZE) {
                log = new SeedkeeperLog(Arrays.copyOfRange(response, 0, SeedkeeperLog.LOG_SIZE));
                logs.add(log);
                response = Arrays.copyOfRange(response, SeedkeeperLog.LOG_SIZE, response.length);

                counter += 1;
                if (counter > 100) { // safe break; should never happen
                    logger.warning("[SatocardCommandSet.seedkeeperPrintLogs] Counter exceeded during log printing: " + counter);
                    break;
                }
            }
        } // while

        // todo: maybe return an object?
//        Object result = new Object(logs, nbTotalLogs, nbAvailLogs);
//        result.add(logs);
//        result.add(nbTotalLogs);
//        result.add(nbAvailLogs);
//        return result;

        return logs;
    }

    /****************************************
     *            PKI commands              *
     ****************************************/

    /**
     * Exports the device's personalization public key.
     *
     * <p>This method retrieves the public key used for device personalization and
     * PKI operations. This key is typically used for:</p>
     * <ul>
     *   <li>Device authentication and identity verification</li>
     *   <li>Certificate chain validation</li>
     *   <li>Secure communication with personalization systems</li>
     *   <li>Challenge-response authentication protocols</li>
     * </ul>
     *
     * <p>The public key is usually set during device manufacturing and cannot
     * be changed by end users.</p>
     *
     * <p><strong>Compatibility:</strong></p>
     * <ul>
     *   <li>Satochip version v0.12-0.5 and higher</li>
     *   <li>All Satodime versions</li>
     *   <li>All Seedkeeper versions</li>
     * </ul>
     *
     * @return the APDU response containing the personalization public key
     * @see #cardExportPersoCertificate()
     * @see #cardChallengeResponsePerso(byte[])
     */
    public APDUResponse cardExportPersoPubkey(){

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_EXPORT_PKI_PUBKEY, 0x00, 0x00, new byte[0]);
        logger.info("SATOCHIPLIB: C-APDU cardExportPersoPubkey:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardExportPersoPubkey:"+ respApdu.toHexString());

        return respApdu;
    }

    /**
     * Exports the device's personalization certificate in PEM format.
     *
     * <p>This method retrieves the X.509 certificate associated with the device's
     * personalization key. The certificate is transmitted in chunks due to APDU
     * size limitations and assembled into a complete PEM-formatted certificate.</p>
     *
     * <p>The certificate contains:</p>
     * <ul>
     *   <li>Device public key</li>
     *   <li>Certificate authority signatures</li>
     *   <li>Device identification information</li>
     *   <li>Validity periods and usage constraints</li>
     * </ul>
     *
     * <p>This certificate can be used to verify device authenticity and establish
     * trust in the device's cryptographic operations.</p>
     *
     * <p><strong>Compatibility:</strong></p>
     * <ul>
     *   <li>Satochip version v0.12-0.5 and higher</li>
     *   <li>All Satodime versions</li>
     *   <li>All Seedkeeper versions</li>
     * </ul>
     *
     * @return the complete certificate in PEM format, or error message if failed
     * @throws APDUException if certificate retrieval fails
     * @see #cardExportPersoPubkey()
     * @see #cardVerifyAuthenticity()
     */
    public String cardExportPersoCertificate() throws APDUException {

        // init
        byte p1 = 0x00;
        byte p2 = 0x01; // init
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_EXPORT_PKI_CERTIFICATE, p1, p2, new byte[0]);
        logger.info("SATOCHIPLIB: C-APDU cardExportPersoCertificate - init:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardExportPersoCertificate - init:"+ respApdu.toHexString());
        respApdu.checkOK();
        int sw = respApdu.getSw();
        byte[] response = null;
        int certificate_size = 0;
        if (sw == 0x9000){
            response= respApdu.getData();
            certificate_size= (response[0] & 0xFF) * 256 + (response[1] & 0xFF);
            logger.warning("SATOCHIPLIB: personalization certificate export: code:" + sw + "certificate size: " + certificate_size);
        } else if (sw == 0x6D00){
            logger.warning("SATOCHIPLIB: Error during personalization certificate export: command unsupported(0x6D00)");
            return "Error during personalization certificate export: command unsupported(0x6D00)";
        } else if (sw == 0x0000){
            logger.warning("SATOCHIPLIB: Error during personalization certificate export: no card present(0x0000)");
            return "Error during personalization certificate export: no card present(0x0000)";
        }

        if (certificate_size==0){
            return ""; //new byte[0]; //"(empty)";
        }

        // UPDATE apdu: certificate data in chunks
        p2= 0x02; //update
        byte[] certificate = new byte[certificate_size];//certificate_size*[0]
        short chunk_size = 128;
        byte[] chunk = new byte[chunk_size];
        int remaining_size = certificate_size;
        int cert_offset = 0;
        byte[] data = new byte[4];
        while(remaining_size > 128){
            // data=[ chunk_offset(2b) | chunk_size(2b) ]
            data[0]= (byte) ((cert_offset>>8)&0xFF);
            data[1]= (byte) (cert_offset&0xFF);
            data[2]= (byte) ((chunk_size>>8)&0xFF);;
            data[3]= (byte) (chunk_size & 0xFF);
            plainApdu = new APDUCommand(0xB0, INS_EXPORT_PKI_CERTIFICATE, p1, p2, data);
            logger.warning("SATOCHIPLIB: C-APDU cardExportPersoCertificate - update:"+ plainApdu.toHexString());
            respApdu = this.cardTransmit(plainApdu);
            logger.warning("SATOCHIPLIB: R-APDU cardExportPersoCertificate - update:"+ respApdu.toHexString());
            respApdu.checkOK();
            // update certificate
            response= respApdu.getData();
            System.arraycopy(response, 0, certificate, cert_offset, chunk_size);
            remaining_size-=chunk_size;
            cert_offset+=chunk_size;
        }

        // last chunk
        data[0]= (byte) ((cert_offset>>8)&0xFF);
        data[1]= (byte) (cert_offset&0xFF);
        data[2]= (byte) ((remaining_size>>8)&0xFF);;
        data[3]= (byte) (remaining_size & 0xFF);
        plainApdu = new APDUCommand(0xB0, INS_EXPORT_PKI_CERTIFICATE, p1, p2, data);
        logger.warning("SATOCHIPLIB: C-APDU cardExportPersoCertificate - final:"+ plainApdu.toHexString());
        respApdu = this.cardTransmit(plainApdu);
        logger.warning("SATOCHIPLIB: R-APDU cardExportPersoCertificate - final:"+ respApdu.toHexString());
        respApdu.checkOK();
        // update certificate
        response= respApdu.getData();
        System.arraycopy(response, 0, certificate, cert_offset, remaining_size);
        cert_offset+=remaining_size;

        // parse and return raw certificate
        String cert_pem= parser.convertBytesToStringPem(certificate);
        logger.warning("SATOCHIPLIB: cardExportPersoCertificate checking certificate:" + Arrays.toString(certificate));

        return cert_pem;
    }

    /**
     * Performs a challenge-response authentication with the card's personalization key.
     *
     * <p>This method executes a cryptographic challenge-response protocol to verify that the
     * card possesses the private key corresponding to its personalization certificate. The
     * challenge is signed by the card using its private key, and the signature can be verified
     * using the card's public key.</p>
     *
     * <p>This operation is typically used as part of the card authentication process to ensure
     * the card is genuine and hasn't been cloned or tampered with.</p>
     *
     * <p><strong>Compatibility:</strong></p>
     * <ul>
     *   <li>Satochip version v0.12-0.5 and higher</li>
     *   <li>All Satodime versions</li>
     *   <li>All Seedkeeper versions</li>
     * </ul>
     *
     * @param challenge_from_host a byte array containing the challenge data to be signed by the card.
     *                           Typically 32 bytes of random data generated by the host
     * @return an {@link APDUResponse} containing the card's challenge response and signature
     *         in the response data field
     * @see APDUResponse
     * @see #cardVerifyAuthenticity()
     */
    public APDUResponse cardChallengeResponsePerso(byte[] challenge_from_host){

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_CHALLENGE_RESPONSE_PKI, 0x00, 0x00, challenge_from_host);
        logger.info("SATOCHIPLIB: C-APDU cardChallengeResponsePerso:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardChallengeResponsePerso:"+ respApdu.toHexString());

        return respApdu;
    }

    /**
     * Performs complete authenticity verification of the card.
     *
     * <p>This method executes a comprehensive authentication process to verify that the card
     * is genuine and has not been tampered with. The verification process includes:</p>
     * <ul>
     *   <li>Retrieving the card's personalization certificate</li>
     *   <li>Validating the certificate chain against trusted root certificates</li>
     *   <li>Performing challenge-response authentication to verify key possession</li>
     *   <li>Ensuring the certificate matches the card's actual cryptographic capabilities</li>
     * </ul>
     *
     * <p>The method uses embedded certificate authority certificates to validate the full
     * certificate chain, ensuring the card was properly personalized by an authorized entity.</p>
     *
     * <p><strong>Compatibility:</strong></p>
     * <ul>
     *   <li>Satochip version v0.12-0.5 and higher</li>
     *   <li>All Satodime versions</li>
     *   <li>All Seedkeeper versions</li>
     * </ul>
     *
     * @return a {@link String} array containing verification results:
     *         <ul>
     *           <li>Index 0: "OK" if verification succeeds, "FAIL" if it fails</li>
     *           <li>Index 1: Root CA certificate details</li>
     *           <li>Index 2: Sub-CA certificate details</li>
     *           <li>Index 3: Device certificate details</li>
     *           <li>Index 4: Error message (empty if verification succeeds)</li>
     *         </ul>
     * @see #cardExportPersoCertificate()
     * @see #cardChallengeResponsePerso(byte[])
     */
    public String[] cardVerifyAuthenticity(){

        String txt_error="";
        String txt_ca="(empty)";
        String txt_subca="(empty)";
        String txt_device="(empty)";
        final String FAIL= "FAIL";
        final String OK= "OK";

        // get certificate from device
        String cert_pem="";
        try{
            cert_pem = cardExportPersoCertificate();
            logger.warning("SATOCHIPLIB: Cert PEM: "+ cert_pem);
        } catch (Exception e){
            logger.warning("SATOCHIPLIB: Exception in cardVerifyAuthenticity:"+ e);
            txt_error= "Unable to retrieve device certificate!";
            //String[] out = new String [5];
            //out[0]={"a","b","c","d"};
            String[] out = new String [] {FAIL, txt_ca, txt_subca, txt_device, txt_error};
            return out;
        }

        // verify certificate chain
        boolean isValidated= false;
        PublicKey pubkeyDevice= null;
        try{
            // load certs
            InputStream isCa = this.getClass().getClassLoader().getResourceAsStream("cert/ca.cert");
            InputStream isSubca;
            if (cardType.equals("satochip")) {
                isSubca = this.getClass().getClassLoader().getResourceAsStream("cert/subca-satochip.cert");
            } else if (cardType.equals("seedkeeper")) {
                isSubca = this.getClass().getClassLoader().getResourceAsStream("cert/subca-seedkeeper.cert");
            } else {
                isSubca = this.getClass().getClassLoader().getResourceAsStream("cert/subca-satodime.cert");
            }
            InputStream isDevice = new ByteArrayInputStream(cert_pem.getBytes(StandardCharsets.UTF_8));
            // gen certs
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC"); // without BC provider, validation fails...
            Certificate certCa = certificateFactory.generateCertificate(isCa);
            txt_ca= certCa.toString();
            logger.warning("SATOCHIPLIB: certCa: " + txt_ca);
            Certificate certSubca = certificateFactory.generateCertificate(isSubca);
            txt_subca= certSubca.toString();
            logger.warning("SATOCHIPLIB: certSubca: " + txt_subca);
            Certificate certDevice = certificateFactory.generateCertificate(isDevice);
            logger.warning("SATOCHIPLIB: certDevice: " + certDevice);
            txt_device= certDevice.toString();
            logger.warning("SATOCHIPLIB: txtCertDevice: " + txt_device);

            pubkeyDevice= certDevice.getPublicKey();
            logger.warning("SATOCHIPLIB: certDevice pubkey: " + pubkeyDevice.toString());

            // cert chain
            Certificate[] chain= new Certificate[2];
            chain[0]= certDevice;
            chain[1]= certSubca;
            CertPath certPath = certificateFactory.generateCertPath(Arrays.asList(chain));

            // keystore
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            KeyStore.TrustedCertificateEntry tcEntry= new KeyStore.TrustedCertificateEntry(certCa);
            //KeyStore.TrustedCertificateEntry tcEntry= new KeyStore.TrustedCertificateEntry(certSubca);
            ks.setEntry("SatodimeCA", tcEntry, null);

            // validator
            PKIXParameters params = new PKIXParameters(ks);
            params.setRevocationEnabled(false);
            CertPathValidator certValidator = CertPathValidator.getInstance(CertPathValidator.getDefaultType()); // PKIX
            certValidator.validate(certPath, params);
            isValidated=true;
            logger.info("SATOCHIPLIB: Certificate chain validated!");

        }catch (Exception e){
            logger.warning("SATOCHIPLIB: Exception in cardVerifyAuthenticity:"+ e);
            e.printStackTrace();
            isValidated=false;
            txt_error= "Failed to validate certificate chain! \r\n\r\n" + e.toString();
            String[] out = new String [] {FAIL, txt_ca, txt_subca, txt_device, txt_error};
            return out;
        }

        // perform challenge-response with the card to ensure that the key is correctly loaded in the device
        try{
            SecureRandom random = new SecureRandom();
            byte[] challenge_from_host= new byte[32];
            random.nextBytes(challenge_from_host);
            APDUResponse rapduChalresp= cardChallengeResponsePerso(challenge_from_host);
            byte[][] parsedData= parser.parseVerifyChallengeResponsePerso(rapduChalresp);
            byte[] challenge_from_device= parsedData[0];
            byte[] sig= parsedData[1];

            // build challenge byte[]
            int offset=0;
            String chalHeaderString=  "Challenge:";
            byte[] chalHeaderBytes= chalHeaderString.getBytes(StandardCharsets.UTF_8);
            byte[] chalFullBytes= new byte[chalHeaderBytes.length + 32 + 32];
            System.arraycopy(chalHeaderBytes, 0, chalFullBytes, offset, chalHeaderBytes.length);
            offset+= chalHeaderBytes.length;
            System.arraycopy(challenge_from_device, 0, chalFullBytes, offset, 32);
            offset+= 32;
            System.arraycopy(challenge_from_host, 0, chalFullBytes, offset, 32);

            // verify sig with pubkeyDevice
            byte[] pubkey= new byte[65];
            byte[] pubkeyEncoded= pubkeyDevice.getEncoded();
            System.arraycopy(pubkeyEncoded, (pubkeyEncoded.length-65), pubkey, 0, 65); // extract pubkey from ASN1 encoding
            boolean isChalrespOk= parser.verifySig(chalFullBytes, sig, pubkey);
            if (!isChalrespOk){
                throw new RuntimeException("Failed to verify challenge-response signature!");
            }
            // TODO: pubkeyDevice should be equal to authentikey
        }catch (Exception e){
            logger.warning("SATOCHIPLIB: Exception in cardVerifyAuthenticity:"+ e);
            e.printStackTrace();
            txt_error= "Failed to verify challenge-response! \r\n\r\n" + e.toString();
            String[] out = new String [] {FAIL, txt_ca, txt_subca, txt_device, txt_error};
            return out;
        }

        String[] out =  new String [] {OK, txt_ca, txt_subca, txt_device, txt_error};
        return out;
    }

}