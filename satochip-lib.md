# satochip-lib Documentation

This document outlines the public methods available in the `satochip-lib` library, primarily focusing on the `SatochipCommandSet`, `SatochipParser`, and `SecureChannelSession` classes.

## `org.satochip.client.SatochipCommandSet`

This class is used to send APDU commands to the Satochip, Satodime, or SeedKeeper applet. Each method generally corresponds to an APDU command.

### Constructor

*   `SatochipCommandSet(CardChannel apduChannel)`: Creates a command set instance using the provided card channel.

### Logging

*   `void setLoggerLevel(String level)`: Sets the logger level (e.g., "info", "warning").
*   `void setLoggerLevel(Level level)`: Sets the logger level using `java.util.logging.Level`.

### Status & Information Getters

*   `ApplicationStatus getApplicationStatus()`: Returns the application status obtained from the last successful SELECT command. Returns `null` if no SELECT command has been sent.
*   `SatodimeStatus getSatodimeStatus()`: Retrieves and returns the current status of the Satodime device.
*   `byte[] getSatodimeUnlockSecret()`: Gets the cached Satodime unlock secret.
*   `void setSatodimeUnlockSecret(byte[] unlockSecret)`: Sets the Satodime unlock secret for subsequent operations.
*   `byte[] getAuthentikey()`: Retrieves the Authentikey from the card (for applet version >= v0.12). Caches the result.
*   `String getAuthentikeyHex()`: Retrieves the Authentikey as a hex string. Caches the result.
*   `byte[] getBip32Authentikey()`: Retrieves the BIP32 Authentikey from the card. Caches the result.
*   `String getBip32AuthentikeyHex()`: Retrieves the BIP32 Authentikey as a hex string. Caches the result.
*   `List<byte[]> getPossibleAuthentikeys()`: Returns the list of possible Authentikeys recovered during Secure Channel initiation.
*   `SatochipParser getParser()`: Returns the `SatochipParser` instance associated with this command set.
*   `void setDefaultBip32path(String bip32path)`: Sets the default BIP32 derivation path to use if none is specified in methods like `cardBip32GetExtendedKey`.
*   `byte[] getExtendedKey()`: Returns the cached extended public key derived from the last `cardBip32GetExtendedKey` call. *(Internal/Test use?)*
*   `String getCardLabel()`: Retrieves the label assigned to the card. Returns "(none)" if not set, "(unknown)" on error.

### Core Card Communication

*   `APDUResponse cardTransmit(APDUCommand plainApdu)`: Transmits an APDU command to the card. Handles Secure Channel encryption/decryption and PIN verification retries automatically if needed.
*   `void cardDisconnect()`: Resets the Secure Channel session, clears cached PIN, and application status. Call this when disconnecting from the card.
*   `APDUResponse cardSelect()`: Selects the Satochip, SeedKeeper, or Satodime applet by trying their default AIDs.
*   `APDUResponse cardSelect(String cardType)`: Selects the applet based on the provided type ("satochip", "seedkeeper", or "satodime").
*   `APDUResponse cardGetStatus()`: Sends the GET STATUS command and updates the internal `ApplicationStatus`.
*   `List<byte[]> cardInitiateSecureChannel()`: Initiates the Secure Channel with the card using ECDH. Returns a list of possible authentikeys.
*   `APDUResponse cardExportPkiPubkey()`: Exports the PKI public key from the card (often the same as the Authentikey).
*   `APDUResponse cardExportPersoPubkey()`: Exports the personalization public key from the card. *(Likely same as `cardExportPkiPubkey`)*

### Card Management

*   `APDUResponse cardSetup(byte pin_tries0, byte[] pin0)`: Sets up the card with a PIN code (PIN0). Uses default/random values for other parameters (PUK, PIN1).
*   `APDUResponse cardSetup(byte pin_tries0, byte ublk_tries0, byte[] pin0, byte[] ublk0, byte pin_tries1, byte ublk_tries1, byte[] pin1, byte[] ublk1)`: Sets up the card with detailed parameters for PINs, PUKs (Unblock Keys), and their retry counters.
*   `APDUResponse cardSendResetCommand()`: Sends the reset command to the card (factory reset). Requires specific card state.
*   `Boolean setCardLabel(String label)`: Sets a label for the card. Returns `true` on success.

### PIN Management

*   `void setPin0(byte[] pin)`: Caches the PIN0 locally for use in subsequent commands requiring authentication.
*   `APDUResponse cardVerifyPIN(byte[] pin)`: Verifies the provided PIN against the card. Caches the PIN locally on success. Throws exceptions on failure (WrongPIN, BlockedPIN).
*   `APDUResponse cardVerifyPIN()`: Verifies the cached PIN0 against the card. Throws exceptions on failure.
*   `APDUResponse cardChangePin(byte[] oldPin, byte[] newPin)`: Changes the card's PIN. Caches the new PIN locally on success. Throws exceptions on failure.
*   `APDUResponse cardUnblockPin(byte[] puk)`: Unblocks a blocked PIN using the corresponding PUK (Unblock Key). Throws exceptions on failure.

### BIP32 (Satochip/SeedKeeper)

*   `APDUResponse cardBip32ImportSeed(byte[] masterseed)`: Imports a BIP32 master seed onto the card. Requires prior PIN verification.
*   `APDUResponse cardResetSeed(byte[] pin, byte[] chalresponse)`: Resets the BIP32 seed on the card. Requires PIN and optionally a 2FA challenge response.
*   `byte[][] cardBip32GetExtendedKey()`: Derives the extended key (public or private) using the default BIP32 path. Returns `[key, chaincode]`.
*   `byte[][] cardBip32GetExtendedKey(String stringPath, Byte flags, Integer sid)`: Derives the extended key (public or private) for a specific BIP32 path.
    *   `stringPath`: BIP32 derivation path (e.g., "m/44'/0'/0'/0/0").
    *   `flags`: Controls derivation options (e.g., private key derivation, BIP85). See `Constants.java`.
    *   `sid`: Seed ID (for SeedKeeper).
*   `String cardBip32GetXpub(String path, long xtype, Integer sid)`: Derives and returns the extended public key (xpub) in Base58Check format for the given path and type (e.g., `Constants.XPUB_TYPE_BTC`).

### Signatures (Satochip)

*   `APDUResponse cardSignTransactionHash(byte keynbr, byte[] txhash, byte[] chalresponse)`: Signs a 32-byte transaction hash using the key derived from the current BIP32 state. Requires prior PIN verification and optionally a 2FA challenge response.

### Satodime Specific Commands

*   `APDUResponse satodimeGetStatus()`: Gets the overall status of the Satodime card. Updates internal `SatodimeStatus`.
*   `APDUResponse satodimeGetKeyslotStatus(int keyNbr)`: Gets the status of a specific key slot.
*   `APDUResponse satodimeSetKeyslotStatusPart0(int keyNbr, int RFU1, int RFU2, int key_asset, byte[] key_slip44, byte[] key_contract, byte[] key_tokenid)`: Sets metadata (asset type, slip44, contract, tokenid) for a key slot. Requires unlock code.
*   `APDUResponse satodimeSetKeyslotStatusPart1(int keyNbr, byte[] key_data)`: Sets additional data for a key slot. Requires unlock code.
*   `APDUResponse satodimeGetPubkey(int keyNbr)`: Retrieves the public key from a specific key slot.
*   `APDUResponse satodimeGetPrivkey(int keyNbr)`: Retrieves the private key from a specific key slot. Requires unlock code. Marks the slot as *unsealed*.
*   `APDUResponse satodimeSealKey(int keyNbr, byte[] entropy_user)`: Seals a key slot, preventing further private key retrieval without unsealing. Requires unlock code and user entropy.
*   `APDUResponse satodimeUnsealKey(int keyNbr)`: Unseals a key slot, allowing private key retrieval again. Requires unlock code.
*   `APDUResponse satodimeResetKey(int keyNbr)`: Resets a specific key slot to its initial state (new key generated). Requires unlock code.
*   `APDUResponse satodimeInitiateOwnershipTransfer()`: Initiates the ownership transfer process. Requires unlock code.

### SeedKeeper Specific Commands

*   `SeedkeeperStatus seedkeeperGetStatus()`: Gets the status of the SeedKeeper card.
*   `SeedkeeperSecretHeader seedkeeperGenerateMasterseed(int seedSize, SeedkeeperExportRights exportRights, String label)`: **DEPRECATED (v0.1)**. Generates a master seed on the SeedKeeper. Use `seedkeeperGenerateRandomSecret`.
*   `List<SeedkeeperSecretHeader> seedkeeperGenerateRandomSecret(...)`: Generates a random secret (master seed, key, etc.) on the SeedKeeper.
    *   `stype`: Type of secret (`SeedkeeperSecretType`).
    *   `subtype`: Subtype (depends on `stype`).
    *   `size`: Size in bytes (16-64).
    *   `saveEntropy`: Whether to save the generated entropy as a separate secret.
    *   `entropy`: Optional user-provided entropy.
    *   `exportRights`: Export permissions (`SeedkeeperExportRights`).
    *   `label`: Label for the secret.
*   `SeedkeeperSecretHeader seedkeeperImportSecret(SeedkeeperSecretObject secretObject)`: Imports a secret (plain or encrypted) onto the SeedKeeper.
*   `SeedkeeperSecretObject seedkeeperExportSecret(int sid, Integer sidPubKey)`: Exports a secret from the SeedKeeper. Can be exported encrypted if `sidPubKey` (the SID of a public key secret) is provided.
*   `SeedkeeperSecretObject seedkeeperExportSecretToSatochip(int sid, Integer sidPubKey)`: Exports a secret encrypted specifically for import into a Satochip device using the target Satochip's public key (`sidPubKey`).
*   `APDUResponse seedkeeperResetSecret(int sid)`: Deletes a secret from the SeedKeeper.
*   `List<SeedkeeperSecretHeader> seedkeeperListSecretHeaders()`: Lists the headers of all secrets stored on the SeedKeeper.
*   `List<SeedkeeperLog> seedkeeperPrintLogs(Boolean printAll)`: Retrieves logs recorded by the SeedKeeper.

### PKI & Authenticity Verification

*   `String cardExportPersoCertificate()`: Exports the device's personalization certificate in PEM format.
*   `APDUResponse cardChallengeResponsePerso(byte[] challenge_from_host)`: Performs a challenge-response operation using the card's personalization private key.
*   `String[] cardVerifyAuthenticity()`: Verifies the authenticity of the card.
    1.  Exports the device certificate.
    2.  Validates the certificate chain against bundled CA/SubCA certificates.
    3.  Performs a challenge-response to ensure the card possesses the corresponding private key.
    *   **Returns:** A `String` array: `[Status (OK/FAIL), CA Cert Info, SubCA Cert Info, Device Cert Info, Error Message (if FAIL)]`.

## `org.satochip.client.SatochipParser`

Provides utility methods for parsing APDU responses and handling cryptographic operations related to the Satochip library.

### Constructor

*   `SatochipParser()`: Default constructor.

### Utility Methods

*   `byte[] compressPubKey(byte[] pubkey)`: Compresses an uncompressed SECP256k1 public key (65 bytes) into compressed format (33 bytes). Returns input if already compressed.
*   `String getBip32PathParentPath(String bip32path)`: Returns the parent path string for a given BIP32 path (e.g., "m/44'/0'/0'" for "m/44'/0'/0'/0").
*   `Bip32Path parseBip32PathToBytes(String bip32path)`: Parses a BIP32 path string into a `Bip32Path` object containing the path depth and byte representation.
*   `byte[] parseInitiateSecureChannel(APDUResponse rapdu)`: Parses the response from `INS_INIT_SECURE_CHANNEL` to recover the *session* public key.
*   `List<byte[]> parseInitiateSecureChannelGetPossibleAuthentikeys(APDUResponse rapdu)`: Parses the response from `INS_INIT_SECURE_CHANNEL` to recover possible *authentikeys*. Returns one key if the card provides the authentikey's x-coordinate, otherwise returns two possible keys.
*   `byte[] parseBip32GetAuthentikey(APDUResponse rapdu)`: Parses the response from `INS_BIP32_GET_AUTHENTIKEY` to extract the authentikey public key.
*   `byte[] parseExportPkiPubkey(APDUResponse rapdu)`: Parses the response from `INS_EXPORT_PKI_PUBKEY` to extract the public key.
*   `byte[][] parseBip32GetExtendedKey(APDUResponse rapdu)`: Parses the response from `INS_BIP32_GET_EXTENDED_KEY` to extract the derived key and chain code. Returns `[key, chaincode]`.
*   `byte[] parseSatodimeGetPubkey(APDUResponse rapdu)`: Parses the response from `INS_GET_SATODIME_PUBKEY`.
*   `HashMap<String, byte[]> parseSatodimeGetPrivkey(APDUResponse rapdu)`: Parses the response from `INS_GET_SATODIME_PRIVKEY`. Returns a map containing "privkey" and "pubkey".
*   `byte[][] parseVerifyChallengeResponsePerso(APDUResponse rapdu)`: Parses the response from `INS_CHALLENGE_RESPONSE_PKI`. Returns `[challenge_from_device, signature]`.
*   `byte[] recoverPubkey(byte[] msg, byte[] sig, byte[] coordx)`: Recovers an ECDSA public key from a message, signature (DER format), and the known x-coordinate of the public key.
*   `List<byte[]> recoverPossiblePubkeys(byte[] msg, byte[] sig)`: Recovers the two possible ECDSA public keys from a message and signature (DER format) when the x-coordinate is unknown.
*   `boolean verifySig(byte[] msg, byte[] dersig, byte[] pub)`: Verifies an ECDSA signature (DER format) against a message and public key.
*   `String convertBytesToStringPem(byte[] certBytes)`: Converts raw certificate bytes into PEM format string.
*   `String toHexString(byte[] raw)`: Converts a byte array to its hexadecimal string representation.
*   `byte[] fromHexString(String hex)`: Converts a hexadecimal string to a byte array.

## `org.satochip.client.SecureChannelSession`

Handles the establishment and management of an encrypted communication channel with the card based on ECDH key exchange.

### Constructor

*   `SecureChannelSession()`: Initializes the session object and generates the client's ECDH key pair.

### Session Management

*   `void initiateSecureChannel(byte[] keyData)`: Establishes the secure channel using the card's public key (`keyData` from `INS_INIT_SECURE_CHANNEL` response) and the client's keypair. Derives session encryption and MAC keys.
*   `APDUCommand encrypt_secure_channel(APDUCommand plainApdu)`: Encrypts a plain APDU command using the established session keys (AES-CBC) and adds a MAC. Returns the encrypted command wrapped in an `INS_PROCESS_SECURE_CHANNEL` APDU.
*   `APDUResponse decrypt_secure_channel(APDUResponse encryptedApdu)`: Decrypts the data field of an `INS_PROCESS_SECURE_CHANNEL` response APDU using the session keys. Returns an `APDUResponse` containing the decrypted APDU data and SW=9000 (does not verify MAC or original SW).
*   `boolean initializedSecureChannel()`: Returns `true` if the secure channel has been successfully initialized.
*   `byte[] getPublicKey()`: Returns the public key generated by the client for the ECDH key exchange.
*   `void resetSecureChannel()`: Resets the secure channel state, marking it as uninitialized. 