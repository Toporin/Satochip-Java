package org.satochip.client.seedkeeper;

import org.bitcoinj.core.Sha256Hash;

import java.math.BigInteger;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class SeedkeeperSecretObject {
    private byte[] secretBytes;
    private SeedkeeperSecretHeader secretHeader;
    private boolean isEncrypted;
    private SeedkeeperSecretEncryptedParams secretEncryptedParams;

    public SeedkeeperSecretObject(byte[] secretBytes, SeedkeeperSecretHeader secretHeader, boolean isEncrypted, SeedkeeperSecretEncryptedParams secretEncryptedParams) {
        this.secretBytes = secretBytes;
        this.secretHeader = secretHeader;
        this.isEncrypted = isEncrypted;
        this.secretEncryptedParams = secretEncryptedParams;
    }

    public SeedkeeperSecretObject(byte[] secretBytes, SeedkeeperSecretHeader secretHeader) {
        this(secretBytes, secretHeader, false, null);
    }

    public SeedkeeperSecretObject(SeedkeeperSecretHeader secretHeader) {
        this(new byte[0], secretHeader, false, null);
    }

    // Getters and Setters
    public byte[] getSecretBytes() {
        return secretBytes;
    }

    public void setSecretBytes(byte[] secretBytes) {
        this.secretBytes = secretBytes;
    }

    public SeedkeeperSecretHeader getSecretHeader() {
        return secretHeader;
    }

    public void setSecretHeader(SeedkeeperSecretHeader secretHeader) {
        this.secretHeader = secretHeader;
    }

    public boolean isEncrypted() {
        return isEncrypted;
    }

    public void setEncrypted(boolean encrypted) {
        isEncrypted = encrypted;
    }

    public SeedkeeperSecretEncryptedParams getSecretEncryptedParams() {
        return secretEncryptedParams;
    }

    public void setSecretEncryptedParams(SeedkeeperSecretEncryptedParams secretEncryptedParams) {
        this.secretEncryptedParams = secretEncryptedParams;
    }

    public byte[] getFingerprintFromSecret() {
        if (isEncrypted) {
            return secretHeader.fingerprintBytes;
        }

        byte[] secretHash = Sha256Hash.hash(secretBytes);
        return Arrays.copyOfRange(secretHash, 0, 4);
    }

    public byte[] getSha512FromSecret() {
        if (isEncrypted) {
            return new byte[0];
        }
        return Sha256Hash.hash(Arrays.copyOfRange(secretBytes, 1, secretBytes.length));
    }

    // todo: Master Password secret, check implementation
    public byte[] getHmacSha512(byte[] salt) {
        if (isEncrypted) {
            return new byte[0];
        }

        byte[] hmac;
        try {
            Mac hmacSHA512 = Mac.getInstance("HmacSHA512");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretBytes,
                    "HmacSHA512");
            hmacSHA512.init(secretKeySpec);
            byte[] digest = hmacSHA512.doFinal(salt);
            BigInteger hash = new BigInteger(1, digest);
            hmac = hash.toByteArray();

        } catch (Exception e) {
            throw new RuntimeException("Problem calculating hmac" + e);
        }
        return hmac;
    }
}

