package org.satochip.client.seedkeeper;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bitcoinj.core.Sha256Hash;

public class SeedkeeperSecretHeader {

    public static final int HEADER_SIZE = 13;

    public int sid;
    public SeedkeeperSecretType type;
    public byte subtype;
    public SeedkeeperSecretOrigin origin;
    public SeedkeeperExportRights exportRights;
    public byte nbExportPlaintext;
    public byte nbExportEncrypted;
    public byte useCounter;
//    public byte rfu2;
    public byte[] fingerprintBytes;
    public String label;

    public SeedkeeperSecretHeader(
            int sid,
            SeedkeeperSecretType type,
            byte subtype,
            SeedkeeperSecretOrigin origin,
            SeedkeeperExportRights exportRights,
            byte nbExportPlaintext,
            byte nbExportEncrypted,
            byte useCounter,
//            byte rfu2,
            byte[] fingerprintBytes,
            String label
    ) {
        this.sid = sid;
        this.type = type;
        this.subtype = subtype;
        this.origin = origin;
        this.exportRights = exportRights;
        this.nbExportPlaintext = nbExportPlaintext;
        this.nbExportEncrypted = nbExportEncrypted;
        this.useCounter = useCounter;
//        this.rfu2 = rfu2;
        this.fingerprintBytes = fingerprintBytes;
        this.label = label;
    }

    public SeedkeeperSecretHeader(byte[] response) throws Exception {
        int responseLength = response.length;
        if (responseLength < SeedkeeperSecretHeader.HEADER_SIZE + 2) {
            throw new Exception("wrongResponseLength: " + responseLength + " " + SeedkeeperSecretHeader.HEADER_SIZE + 2);
        }

        int offset = 0;
        sid = 256 * (response[0] & 0xFF) + (response[1] & 0xFF);
        type = SeedkeeperSecretType.fromRawValue(response[2]);
        subtype = response[12];
        origin = SeedkeeperSecretOrigin.fromRawValue(response[3]);
        exportRights = SeedkeeperExportRights.fromRawValue(response[4]);
        nbExportPlaintext = response[5];
        nbExportEncrypted = response[6];
        useCounter = response[7];
        fingerprintBytes = Arrays.copyOfRange(response, 8, 12);
//        rfu2 = response[13];
        int labelSize = response[14];
        if (responseLength < SeedkeeperSecretHeader.HEADER_SIZE + 2 + labelSize) {
            throw new Exception("wrongResponseLength: " + responseLength + " " + SeedkeeperSecretHeader.HEADER_SIZE + 2 + labelSize);
        }
        byte[] labelBytes = Arrays.copyOfRange(response, 15, 15 + labelSize);
        label = new String(labelBytes, StandardCharsets.UTF_8);
    }

    public byte[] getHeaderBytes() {
        byte[] labelBytes = label.getBytes(StandardCharsets.UTF_8);
        byte labelSize = (byte) labelBytes.length;
        byte[] headerBytes = new byte[] {
                type.getValue(),
                origin.getValue(),
                exportRights.getValue(),
                nbExportPlaintext,
                nbExportEncrypted,
                useCounter
        };

        byte[] result = new byte[headerBytes.length + fingerprintBytes.length + 3 + labelBytes.length];
        int index = 0;

        System.arraycopy(headerBytes, 0, result, index, headerBytes.length);
        index += headerBytes.length;
        System.arraycopy(fingerprintBytes, 0, result, index, fingerprintBytes.length);
        index += fingerprintBytes.length;
        result[index++] = subtype;
        result[index++] = 0; //rfu2 not used
        result[index++] = labelSize;
        System.arraycopy(labelBytes, 0, result, index, labelBytes.length);

        return result;
    }

    public static byte[] getFingerprintBytes(byte[] secretBytes) {
        byte[] secretHash = Sha256Hash.hash(secretBytes);
        return Arrays.copyOfRange(secretHash, 0, 4);
    }
}

