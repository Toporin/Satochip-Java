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
 * This class is used to send APDU to the applet. Each method corresponds to an APDU as defined in the APPLICATION.md
 * file. Some APDUs map to multiple methods for the sake of convenience since their payload or response require some
 * pre/post processing.
 */
public class SatochipCommandSet {

    private static final Logger logger = Logger.getLogger("org.satochip.client");

    private final CardChannel apduChannel;
    private SecureChannelSession secureChannel;
    private ApplicationStatus status;
    private SatochipParser parser = null;

    private byte[] pin0 = null;
    private byte[] authentikey = null;
    private String authentikeyHex = null;
    private String defaultBip32path = null;
    private byte[] extendedKey = null;
    private String extendedKeyHex = null;
    private byte[] extendedPrivKey = null;
    private String extendedPrivKeyHex = null;


    // Satodime, SeedKeeper or Satochip?
    private String cardType = null;
    private String certPem = null; // PEM certificate of device, if any

    // satodime
    SatodimeStatus satodimeStatus = null;

    // seedkeeper
    SeedkeeperStatus seedkeeperStatus = null;


    public static final byte[] SATOCHIP_AID = Hex.decode("5361746f43686970"); //SatoChip
    public static final byte[] SEEDKEEPER_AID = Hex.decode("536565644b6565706572"); //SeedKeeper
    public static final byte[] SATODIME_AID = Hex.decode("5361746f44696d65"); //SatoDime 

    public final static byte DERIVE_P1_SOURCE_MASTER = (byte) 0x00;
    public final static byte DERIVE_P1_SOURCE_PARENT = (byte) 0x40;
    public final static byte DERIVE_P1_SOURCE_CURRENT = (byte) 0x80;

    /**
     * Creates a SatochipCommandSet using the given APDU Channel
     *
     * @param apduChannel APDU channel
     */
    public SatochipCommandSet(CardChannel apduChannel) {
        this.apduChannel = apduChannel;
        this.secureChannel = new SecureChannelSession();
        this.parser = new SatochipParser();
        this.satodimeStatus = new SatodimeStatus();
        logger.setLevel(Level.WARNING);
    }

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

    public void setLoggerLevel(Level level) {
        logger.setLevel(level);
    }

    /**
     * Returns the application info as stored from the last sent SELECT command. Returns null if no succesful SELECT
     * command has been sent using this command set.
     *
     * @return the application info object
     */
    public ApplicationStatus getApplicationStatus() {
        return status;
    }

    public SatodimeStatus getSatodimeStatus() {
        this.satodimeGetStatus();
        return this.satodimeStatus;
    }

    public byte[] getSatodimeUnlockSecret() {
        return this.satodimeStatus.getUnlockSecret();
    }

    public void setSatodimeUnlockSecret(byte[] unlockSecret) {
        this.satodimeStatus.setUnlockSecret(unlockSecret);
    }

    /****************************************
     *                AUTHENTIKEY                    *
     ****************************************/
    public byte[] getAuthentikey() {
        if (authentikey == null) {
            cardGetAuthentikey();
        }
        return authentikey;
    }

    public String getAuthentikeyHex() {
        if (authentikeyHex == null) {
            cardGetAuthentikey();
        }
        return authentikeyHex;
    }

    public byte[] getBip32Authentikey() {
        if (authentikey == null) {
            cardBip32GetAuthentikey();
        }
        return authentikey;
    }

    public String getBip32AuthentikeyHex() {
        if (authentikeyHex == null) {
            cardBip32GetAuthentikey();
        }
        return authentikeyHex;
    }

    public SatochipParser getParser() {
        return parser;
    }

    public void setDefaultBip32path(String bip32path) {
        defaultBip32path = bip32path;
    }

    /**
     * Set the SecureChannel object
     *
     * @param secureChannel secure channel
     */
    protected void setSecureChannel(SecureChannelSession secureChannel) {
        this.secureChannel = secureChannel;
    }

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
                        // get card's public key
                        APDUResponse secChannelRapdu = cardInitiateSecureChannel();
                        byte[] pubkey = parser.parseInitiateSecureChannel(secChannelRapdu);
                        // setup secure channel
                        secureChannel.initiateSecureChannel(pubkey);
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

    public void cardDisconnect() {
        secureChannel.resetSecureChannel();
        status = null;
        pin0 = null;
    }

    /**
     * Selects a Satochip/Satodime/SeedKeeper instance. The applet is assumed to have been installed with its default AID.
     *
     * @return the raw card response
     * @throws IOException communication error
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

    public APDUResponse cardGetStatus() {
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_STATUS, 0x00, 0x00, new byte[0]);

        logger.info("SATOCHIPLIB: C-APDU cardGetStatus:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardGetStatus:" + respApdu.toHexString());

        status = new ApplicationStatus(respApdu);
        logger.info("SATOCHIPLIB: Status from cardGetStatus:" + status.toString());

        return respApdu;
    }

    public APDUResponse cardInitiateSecureChannel() throws IOException {

        byte[] pubkey = secureChannel.getPublicKey();

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_INIT_SECURE_CHANNEL, 0x00, 0x00, pubkey);

        logger.info("SATOCHIPLIB: C-APDU cardInitiateSecureChannel:" + plainApdu.toHexString());
        APDUResponse respApdu = apduChannel.send(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardInitiateSecureChannel:" + respApdu.toHexString());

        return respApdu;
    }

    // only valid for v0.12 and higher
    public APDUResponse cardGetAuthentikey() {

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_EXPORT_AUTHENTIKEY, 0x00, 0x00, new byte[0]);
        logger.info("SATOCHIPLIB: C-APDU cardExportAuthentikey:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardExportAuthentikey:" + respApdu.toHexString());

        // parse and recover pubkey
        authentikey = parser.parseBip32GetAuthentikey(respApdu);
        authentikeyHex = parser.toHexString(authentikey);
        logger.info("SATOCHIPLIB: Authentikey from cardExportAuthentikey:" + authentikeyHex);

        return respApdu;
    }

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

    /****************************************
     *                 CARD MGMT                      *
     ****************************************/

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
        logger.info("SATOCHIPLIB: C-APDU cardSetup:" + plainApdu.toHexString());
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


    /****************************************
     *             PIN MGMT                  *
     ****************************************/
    public void setPin0(byte[] pin) {
        this.pin0 = new byte[pin.length];
        System.arraycopy(pin, 0, this.pin0, 0, pin.length);
    }

    public APDUResponse cardVerifyPIN() {

        if (pin0 == null) {
            // TODO: specific exception
            throw new RuntimeException("PIN required!");
        }

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_VERIFY_PIN, 0x00, 0x00, pin0);
        logger.info("SATOCHIPLIB: C-APDU cardVerifyPIN:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardVerifyPIN:" + respApdu.toHexString());

        return respApdu;
    }

    /****************************************
     *                 BIP32                     *
     ****************************************/

    public APDUResponse cardBip32ImportSeed(byte[] masterseed) {
        //TODO: check seed (length...)
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_BIP32_IMPORT_SEED, masterseed.length, 0x00, masterseed);

        logger.info("SATOCHIPLIB: C-APDU cardBip32ImportSeed:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardBip32ImportSeed:" + respApdu.toHexString());

        return respApdu;
    }

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
        logger.info("SATOCHIPLIB: C-APDU cardSignTransactionHash:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardSignTransactionHash:" + respApdu.toHexString());
        // TODO: check SW code for particular status

        return respApdu;
    }

    public APDUResponse cardBip32GetExtendedKey() throws Exception {
        if (defaultBip32path == null) {
            defaultBip32path = "m/44'/60'/0'/0/0";
        }
        return cardBip32GetExtendedKey(defaultBip32path, null);
    }

    public APDUResponse cardBip32GetExtendedKey(String stringPath, Byte flags) throws Exception {
        logger.info("SATOCHIPLIB: cardBip32GetExtendedKey");

        KeyPath keyPath = new KeyPath(stringPath);
        byte[] bytePath = keyPath.getData();
        byte p1 = (byte) (bytePath.length / 4);
        byte optionFlags = (byte) 0x40;
        if (flags != null) {
            optionFlags = flags;
        }
        byte p2 = optionFlags;

        while (true) {
            APDUCommand plainApdu = new APDUCommand(
                    0xB0,
                    INS_BIP32_GET_EXTENDED_KEY,
                    p1,
                    p2,
                    bytePath
            );
            logger.info("SATOCHIPLIB: C-APDU cardBip32GetExtendedKey:" + plainApdu.toHexString());
            APDUResponse respApdu = this.cardTransmit(plainApdu);
            logger.info("SATOCHIPLIB: R-APDU cardBip32GetExtendedKey:" + respApdu.toHexString());
            if (respApdu.getSw() == 0x9C01) {
                logger.info("SATOCHIPLIB: cardBip32GetExtendedKey: Reset memory...");
                // reset memory flag
                p2 = (byte) (p2 ^ 0x80);
                plainApdu = new APDUCommand(
                        0xB0,
                        INS_BIP32_GET_EXTENDED_KEY,
                        p1,
                        p2,
                        bytePath
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
                        respApdu.getSw()
                );
            }
            // success
            if (respApdu.getSw() == 0x9000) {
                logger.info("SATOCHIPLIB: cardBip32GetExtendedKey: return 0x9000...");
                byte[] response = respApdu.getData();
                if ((optionFlags & 0x04) == 0x04) { // BIP85
                    //todo: enable?
//                    extendedKey = parser.parseBip85GetExtendedKey(respApdu);
//                    extendedKeyHex = parser.toHexString(extendedKey);
                } else if ((optionFlags & 0x02) == 0x00) { // BIP32 pubkey
                    if ((response[32] & 0x80) == 0x80) {
                        logger.info("SATOCHIPLIB: cardBip32GetExtendedKey: Child Derivation optimization...");
                        throw new Exception("Unsupported legacy option during BIP32 derivation");
                    }
                    extendedKey = parser.parseBip32GetExtendedKey(respApdu);
                    extendedKeyHex = parser.toHexString(extendedKey);
                } else { // BIP32 privkey
                    extendedPrivKey = parser.parseBip32GetExtendedKey(respApdu);
                    extendedPrivKeyHex = parser.toHexString(extendedPrivKey);
                }
                return respApdu;
            }
        }
    }

    // todo: cardBip32GetXpub in progress

    public static byte[] digestRipeMd160(byte[] input) {
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(input, 0, input.length);
        byte[] ripmemdHash = new byte[20];
        digest.doFinal(ripmemdHash, 0);
        return ripmemdHash;
    }

    // public APDUResponse cardSignMessage(int keyNbr, byte[] pubkey, String message, byte[] hmac, String altcoin){
    // }

    /****************************************
     *             SIGNATURES              *
     ****************************************/

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

    /****************************************
     *               2FA commands            *
     ****************************************/


    /****************************************
     *                SATODIME              *
     ****************************************/


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

    public APDUResponse satodimeGetKeyslotStatus(int keyNbr) {

        byte keyslot = (byte) (keyNbr % 256);
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_SATODIME_KEYSLOT_STATUS, keyslot, 0x00, new byte[0]);
        logger.info("SATOCHIPLIB: C-APDU satodimeGetKeyslotStatus:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU satodimeGetKeyslotStatus:" + respApdu.toHexString());

        return respApdu;
    }

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

    public APDUResponse satodimeGetPubkey(int keyNbr) {

        byte keyslot = (byte) (keyNbr % 256);
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_SATODIME_PUBKEY, keyslot, 0x00, new byte[0]);

        logger.info("SATOCHIPLIB: C-APDU satodimeGetPubkey:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU satodimeGetPubkey:" + respApdu.toHexString());

        return respApdu;
    }

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

    public APDUResponse seedkeeperGetStatus() {
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_SEEDKEEPER_STATUS, 0x00, 0x00, new byte[0]);

        logger.info("SATOCHIPLIB: C-APDU seedkeeperGetStatus:" + plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU seedkeeperGetStatus:" + respApdu.toHexString());

        seedkeeperStatus.updateStatus(respApdu);
        return respApdu;
    }

    /**
     * This function generates a master seed randomly within the Seedkeeper
     * DEPRECATED: use only for Seedkeeper v0.1, for Seedkeeper v0.2, use preferrably seedkeeperGenerateRandomSecret()
     * <p>
     * - parameter seedSize: seed size in byte (between 16-64)
     * - parameter exportRights: export rights for generated secret
     * - parameter label: label
     * <p>
     * - Returns: Response adpu & SeedkeeperSecretHeader data
     */
    public SeedkeeperMasterSeedResult seedkeeperGenerateMasterseed(int seedSize, SeedkeeperExportRights exportRights, String label) throws Exception {
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
        List<SeedkeeperSecretHeader> headers = new ArrayList<>();
        headers.add(header);

        return new SeedkeeperMasterSeedResult(respApdu, headers);
    }

    public SeedkeeperMasterSeedResult seedkeeperGenerateRandomSecret(
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

        return new SeedkeeperMasterSeedResult(respApdu, headers);
    }

    public SeedkeeperImportSecretResult seedkeeperImportSecret(
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

        logger.info("SATOCHIPLIB: C-APDU seedkeeperImportSecret:" + plainApdu.toHexString());
        APDUResponse respApdu = cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU seedkeeperImportSecret:" + respApdu.toHexString());

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

            logger.info("SATOCHIPLIB: C-APDU seedkeeperImportSecret:" + plainApdu.toHexString());
            respApdu = this.cardTransmit(plainApdu);
            logger.info("SATOCHIPLIB: R-APDU seedkeeperImportSecret:" + respApdu.toHexString());
            respApdu.checkOK();
            secretOffset += chunkSize;
            secretRemaining += chunkSize;
        }

        byte[] chunk = new byte[chunkSize + 2];
        chunk[0] = (byte) (chunkSize >> 8);
        chunk[1] = (byte) (chunkSize & 0xFF);
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

        logger.info("SATOCHIPLIB: C-APDU seedkeeperImportSecret:" + plainApdu.toHexString());
        respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU seedkeeperImportSecret:" + respApdu.toHexString());
        respApdu.checkOK();

        byte[] response = respApdu.getData();
        int responseLength = response.length;

        if (responseLength < 6) {
            throw new RuntimeException("Wrong response length: " + responseLength);
        }

        int sid = 256 * (response[0] & 0xFF) + (response[1] & 0xFF);

        byte[] fingerprintFromSeedkeeper = Arrays.copyOfRange(response, 2, 6);
        byte[] fingerprintFromSecret = secretObject.getFingerprintFromSecret();

        if(Arrays.equals(fingerprintFromSecret, fingerprintFromSeedkeeper)) {
            logger.info("SATOCHIPLIB: seedkeeperImportSecret: Fingerprints match!");
        } else {
            logger.info("SATOCHIPLIB: seedkeeperImportSecret: Fingerprints mismatch:" +
                    " expected" + Arrays.toString(fingerprintFromSecret) +
                    "but recovered" +
                    Arrays.toString(fingerprintFromSeedkeeper)
            );
        }
        return new SeedkeeperImportSecretResult(respApdu, sid, fingerprintFromSeedkeeper);
    }

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
//        byte[] sigBytes;
        while (true) {
            plainApdu = new APDUCommand(
                    0xB0,
                    INS_EXPORT_SEEDKEEPER_SECRET,
                    isSecureExport ? (byte) 0x02 : (byte) 0x01,
                    (byte) 0x02,
                    new byte[0]
            );
            logger.info("SATOCHIPLIB: C-APDU seedkeeperExportSecret:" + plainApdu.toHexString());
            respApdu = this.cardTransmit(plainApdu);
            logger.info("SATOCHIPLIB: R-APDU seedkeeperExportSecret:" + respApdu.toHexString());
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

        respApdu.checkOK();

        while(respApdu.getSw1() != 0x90 && respApdu.getSw2() != 0x00) {
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
    
    public APDUResponse cardExportPersoPubkey(){
        
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_EXPORT_PKI_PUBKEY, 0x00, 0x00, new byte[0]);
        logger.info("SATOCHIPLIB: C-APDU cardExportPersoPubkey:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardExportPersoPubkey:"+ respApdu.toHexString());
        
        return respApdu;
    }
    
    public String cardExportPersoCertificate(){
        
        // init
        byte p1= 0x00;
        byte p2= 0x01; // init
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_EXPORT_PKI_CERTIFICATE, p1, p2, new byte[0]);
        logger.info("SATOCHIPLIB: C-APDU cardExportPersoCertificate - init:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardExportPersoCertificate - init:"+ respApdu.toHexString());
        
        int sw= respApdu.getSw();
        byte[] response=null;
        int certificate_size=0;
        if (sw== 0x9000){
            response= respApdu.getData();
            certificate_size= (response[0] & 0xFF)*256 + (response[1] & 0xFF);
        } else if (sw== 0x6D00){
            logger.warning("SATOCHIPLIB: Error during personalization certificate export: command unsupported(0x6D00)");
            return "Error during personalization certificate export: command unsupported(0x6D00)";
        } else if (sw==0x0000){
            logger.warning("SATOCHIPLIB: Error during personalization certificate export: no card present(0x0000)");
            return "Error during personalization certificate export: no card present(0x0000)";
        }
        
        if (certificate_size==0){
            return ""; //new byte[0]; //"(empty)";
        }               
        
        // UPDATE apdu: certificate data in chunks
        p2= 0x02; //update
        byte[] certificate= new byte[certificate_size];//certificate_size*[0]
        short chunk_size=128;
        byte[] chunk= new byte[chunk_size];
        int remaining_size= certificate_size;
        int cert_offset=0;
        byte[] data= new byte[4];
        while(remaining_size>128){
            // data=[ chunk_offset(2b) | chunk_size(2b) ]
            data[0]= (byte) ((cert_offset>>8)&0xFF);
            data[1]= (byte) (cert_offset&0xFF);
            data[2]= (byte) ((chunk_size>>8)&0xFF);;
            data[3]= (byte) (chunk_size & 0xFF);
            plainApdu = new APDUCommand(0xB0, INS_EXPORT_PKI_CERTIFICATE, p1, p2, data);
            logger.info("SATOCHIPLIB: C-APDU cardExportPersoCertificate - update:"+ plainApdu.toHexString());
            respApdu = this.cardTransmit(plainApdu);
            logger.info("SATOCHIPLIB: R-APDU cardExportPersoCertificate - update:"+ respApdu.toHexString());
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
        logger.info("SATOCHIPLIB: C-APDU cardExportPersoCertificate - final:"+ plainApdu.toHexString());
        respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardExportPersoCertificate - final:"+ respApdu.toHexString());
        // update certificate
        response= respApdu.getData();
        System.arraycopy(response, 0, certificate, cert_offset, remaining_size);
        cert_offset+=remaining_size;
        
        // parse and return raw certificate
        String cert_pem= parser.convertBytesToStringPem(certificate);
        
        return cert_pem;
    }
    
    public APDUResponse cardChallengeResponsePerso(byte[] challenge_from_host){
        
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_CHALLENGE_RESPONSE_PKI, 0x00, 0x00, challenge_from_host);
        logger.info("SATOCHIPLIB: C-APDU cardChallengeResponsePerso:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        logger.info("SATOCHIPLIB: R-APDU cardChallengeResponsePerso:"+ respApdu.toHexString());
        
        return respApdu;
    }
    
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
            cert_pem= cardExportPersoCertificate();
            logger.info("SATOCHIPLIB: Cert PEM: "+ cert_pem);
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
            //TODO: load subca cert depending on card type
            InputStream isSubca = this.getClass().getClassLoader().getResourceAsStream("cert/subca-satodime.cert"); 
            InputStream isDevice = new ByteArrayInputStream(cert_pem.getBytes(StandardCharsets.UTF_8));
            // gen certs
            CertificateFactory certificateFactory= CertificateFactory.getInstance("X.509", "BC"); // without BC provider, validation fails...
            Certificate certCa = certificateFactory.generateCertificate(isCa);
            txt_ca= certCa.toString();
            logger.info("SATOCHIPLIB: certCa: " + txt_ca); 
            Certificate certSubca = certificateFactory.generateCertificate(isSubca);
            txt_subca= certSubca.toString();
            logger.info("SATOCHIPLIB: certSubca: " + txt_subca); 
            Certificate certDevice = certificateFactory.generateCertificate(isDevice);
            txt_device= certDevice.toString();
            logger.info("SATOCHIPLIB: certDevice: " + txt_device); 
            
            pubkeyDevice= certDevice.getPublicKey();
            logger.info("SATOCHIPLIB: certDevice pubkey: " + pubkeyDevice.toString()); 
            
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
