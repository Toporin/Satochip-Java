package org.satochip.client.satocash;

import org.satochip.io.APDUException;
import org.satochip.io.APDUResponse;

/**
 * SatocashStatus.java
 * Satochip-Java
 *
 * Created by Satochip on 23/06/2025.
 */
public class SatocashStatus {

    private boolean setupDone = false;
    private boolean isSeeded = false;
    private boolean needsSecureChannel = false;
    private boolean needs2FA = false;
    private byte protocolMajorVersion = 0;
    private byte protocolMinorVersion = 0;
    private byte appletMajorVersion = 0;
    private byte appletMinorVersion = 0;
    private byte pin0RemainingTries = 0;
    private byte puk0RemainingTries = 0;
    private byte pin1RemainingTries = 0;
    private byte puk1RemainingTries = 0;
    private int protocolVersion = 0; // Using int for unsigned 16-bit

    private byte nfcPolicy = 0;
    private byte pinPolicy = 0;
    private byte rfuPolicy = 0;
    private byte maxNbMints = 0;
    private byte nbMints = 0;
    private byte maxNbKeysets = 0;
    private byte nbKeysets = 0;
    private int maxNbProofs = 0; // Using int for unsigned 16-bit
    private int nbUnspentProofs = 0; // Using int for unsigned 16-bit
    private int nbSpentProofs = 0; // Using int for unsigned 16-bit
    private int nbProofs = 0; // Using int for unsigned 16-bit

    public SatocashStatus(APDUResponse rapdu) throws APDUException {

        if ((rapdu.getSw() == 0x9000) && (rapdu.getData().length >= 4)) {

            byte[] data = rapdu.getData();
            // version
            protocolMajorVersion = data[0];
            protocolMinorVersion = data[1];
            appletMajorVersion = data[2];
            appletMinorVersion = data[3];
            protocolVersion = ((protocolMajorVersion & 0xFF) << 8) + (protocolMinorVersion & 0xFF);

            // pin status
            if (data.length >= 8) {
                pin0RemainingTries = data[4];
                puk0RemainingTries = data[5];
                pin1RemainingTries = data[6];
                puk1RemainingTries = data[7];
                needs2FA = false; // default value
            }
            // 2FA
            if (data.length >= 9) {
                needs2FA = (data[8] == 0x00 ? false : true);
            }
            // RFU
            if (data.length >= 10) {
                isSeeded = (data[9] == 0x00 ? false : true);
            }
            // setup status
            if (data.length >= 11) {
                setupDone = (data[10] == 0x00 ? false : true);
            } else {
                setupDone = true;
            }
            // secure channel
            if (data.length >= 12) {
                needsSecureChannel = (data[11] == 0x00 ? false : true);
            } else {
                needsSecureChannel = false;
                needs2FA = false; // default value
            }
            // NFC policy
            if (data.length >= 13) {
                nfcPolicy = data[12];  // 0:NFC_ENABLED, 1:NFC_DISABLED, 2:NFC_BLOCKED
            } else {
                nfcPolicy = 0x00;  // NFC_ENABLED by default
            }
            // pin policy
            if (data.length >= 14) {
                pinPolicy = data[13];
            }
            // RFU policy
            if (data.length >= 15) {
                rfuPolicy = data[14];
            }
            // satocash settings
            if (data.length >= 16) {
                maxNbMints = data[15];
            }
            if (data.length >= 17) {
                nbMints = data[16];
            }
            if (data.length >= 18) {
                maxNbKeysets = data[17];
            }
            if (data.length >= 19) {
                nbKeysets = data[18];
            }
            if (data.length >= 21) {
                maxNbProofs = ((data[19] & 0xFF) << 8) + (data[20] & 0xFF);
            }
            if (data.length >= 23) {
                nbUnspentProofs = ((data[21] & 0xFF) << 8) + (data[22] & 0xFF);
            }
            if (data.length >= 25) {
                nbSpentProofs = ((data[23] & 0xFF) << 8) + (data[24] & 0xFF);
            }
            nbProofs = nbUnspentProofs + nbSpentProofs;

        } else if (rapdu.getSw() == 0x9c04) {
            setupDone = false;
            isSeeded = false;
            needsSecureChannel = false;
        } else {
            //throw new IllegalArgumentException("Invalid APDU response");
            throw new APDUException(rapdu.getSw(), "Invalid APDU response");
        }
    }

    // Getters
    public boolean isSetupDone() {
        return setupDone;
    }

    public boolean isSeeded() {
        return isSeeded;
    }

    public boolean needsSecureChannel() {
        return needsSecureChannel;
    }

    public boolean needs2FA() {
        return needs2FA;
    }

    public byte getProtocolMajorVersion() {
        return protocolMajorVersion;
    }

    public byte getProtocolMinorVersion() {
        return protocolMinorVersion;
    }

    public byte getAppletMajorVersion() {
        return appletMajorVersion;
    }

    public byte getAppletMinorVersion() {
        return appletMinorVersion;
    }

    public byte getPin0RemainingTries() {
        return pin0RemainingTries;
    }

    public byte getPuk0RemainingTries() {
        return puk0RemainingTries;
    }

    public byte getPin1RemainingTries() {
        return pin1RemainingTries;
    }

    public byte getPuk1RemainingTries() {
        return puk1RemainingTries;
    }

    public int getProtocolVersion() {
        return protocolVersion;
    }

    public byte getNfcPolicy() {
        return nfcPolicy;
    }

    public byte getPinPolicy() {
        return pinPolicy;
    }

    public byte getRfuPolicy() {
        return rfuPolicy;
    }

    public byte getMaxNbMints() {
        return maxNbMints;
    }

    public byte getNbMints() {
        return nbMints;
    }

    public byte getMaxNbKeysets() {
        return maxNbKeysets;
    }

    public byte getNbKeysets() {
        return nbKeysets;
    }

    public int getMaxNbProofs() {
        return maxNbProofs;
    }

    public int getNbUnspentProofs() {
        return nbUnspentProofs;
    }

    public int getNbSpentProofs() {
        return nbSpentProofs;
    }

    public int getNbProofs() {
        return nbProofs;
    }

    @Override
    public String toString() {
        return "setup_done: " + setupDone + "\n" +
                "is_seeded: " + isSeeded + "\n" +
                "needs_2FA: " + needs2FA + "\n" +
                "needs_secure_channel: " + needsSecureChannel + "\n" +
                "protocol_major_version: " + protocolMajorVersion + "\n" +
                "protocol_minor_version: " + protocolMinorVersion + "\n" +
                "applet_major_version: " + appletMajorVersion + "\n" +
                "applet_minor_version: " + appletMinorVersion + "\n" +
                "nfcPolicy: " + nfcPolicy + "\n" +
                "pinPolicy: " + pinPolicy + "\n" +
                "rfuPolicy: " + rfuPolicy + "\n" +
                "satocash_max_nb_mints: " + maxNbMints + "\n" +
                "satocash_nb_mints: " + nbMints + "\n" +
                "satocash_max_nb_keysets: " + maxNbKeysets + "\n" +
                "satocash_nb_keysets: " + nbKeysets + "\n" +
                "satocash_max_nb_proofs: " + maxNbProofs + "\n" +
                "satocash_nb_unspent_proofs: " + nbUnspentProofs + "\n" +
                "satocash_nb_spent_proofs: " + nbSpentProofs + "\n" +
                "satocash_nb_proofs: " + nbProofs;
    }
}