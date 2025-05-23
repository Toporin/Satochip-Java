# Satochip-Java Library Documentation

## Command Reference

### Core Commands (All Card Types)

#### Card Selection and Status

##### `cardSelect()`
Selects the appropriate applet on the card. The `cardSelect()` method is responsible for selecting and activating 
the appropriate applet on the NFC card. Think of it as "opening" the specific application you want to communicate with on the card.
Smartcards can contain multiple applets (applications). Each card type (Satochip, Satodime, Seedkeeper) has its own applet 
with a unique Application Identifier (AID). Before you can send any commands to a specific applet, you need to select it first.

**Parameters:** None  
**Returns:** `APDUResponse` - Selection response  
**Throws:** `IOException`

```java
APDUResponse response = commandSet.cardSelect();
```
When `cardSelect()` is called without parameters, the library tries to detect the card type automatically by 
attempting to select each known applet in sequence:

1. **First**, it tries to select the Satochip applet (AID: `5361746f43686970`)
2. **If that fails**, it tries Seedkeeper (AID: `536565644b6565706572`)
3. **If that fails**, it tries Satodime (AID: `5361746f44696d65`)
4. **If all fail**, it sets the card type as "unknown"

##### `cardSelect(String cardType)`
Selects a specific card type.

**Parameters:**
- `cardType`: "satochip", "seedkeeper", or "satodime"

**Returns:** `APDUResponse`  
**Throws:** `IOException`

##### `cardGetStatus()`
Retrieves the current status of the card.

**Parameters:** None  
**Returns:** `APDUResponse` containing status information  
**Throws:** None

```java
APDUResponse response = commandSet.cardGetStatus();
ApplicationStatus status = commandSet.getApplicationStatus();
```

#### Authentication and Security

##### `cardVerifyPIN(byte[] pin)`
Verifies the PIN to authenticate with the card. This proves the application (and user) is authorized to access the card's sensitive functions.
If the PIN is successfully verified by the card (response code `0x9000`), it is cached by the library and reused when needed. 

WARNING: if multiple wrong PIN values are sent, the PIN can be blocked and a PUK code will be required to unblock the PIN.

**Parameters:**
- `pin`: PIN as byte array. If pin is null and a pin value is cached by the library, it is used for verification.

**Returns:** `APDUResponse`  
**Throws:**
- `WrongPINException` - Incorrect PIN with retry count
- `WrongPINLegacyException` - Legacy wrong PIN format
- `BlockedPINException` - PIN blocked after too many attempts

```java
try {
    byte[] pin = "123456".getBytes(StandardCharsets.UTF_8);
    commandSet.cardVerifyPIN(pin);
} catch (WrongPINException e) {
    int remainingAttempts = e.getRetryAttempts();
    // Handle wrong PIN
}
```

##### `cardChangePin(byte[] oldPin, byte[] newPin)`
Changes the current PIN.

**Parameters:**
- `oldPin`: Current PIN
- `newPin`: New PIN

**Returns:** `APDUResponse`  
**Throws:** Same as `cardVerifyPIN()`

##### `cardUnblockPin(byte[] puk)`
Unblocks a blocked PIN using PUK.

**Parameters:**
- `puk`: PUK (PIN Unblock Key)

**Returns:** `APDUResponse`  
**Throws:** PIN-related exceptions, `ResetToFactoryException`

#### Secure Channel

##### `cardInitiateSecureChannel()`
The `cardInitiateSecureChannel()` method establishes an encrypted communication channel between your application 
and the smartcard. This ensures that all subsequent commands and responses are encrypted and authenticated, 
protecting sensitive data from eavesdropping or tampering.

**Parameters:** None  
**Returns:** `List<byte[]>` - Possible authentication keys  
**Throws:** `IOException`

```java
List<byte[]> authKeys = commandSet.cardInitiateSecureChannel();
```

Notes on secure channel:
1. **Automatic handling**: The library usually establishes secure channel automatically when needed
2. **Session-based**: Secure channel lasts for the duration of the connection
3. **Transparent**: Once established, encryption and decryption are handled automatically
4. **Required for sensitive ops**: most commands will fail without secure channel

The secure channel is essentially like establishing an HTTPS connection with the smartcard - it ensures that 
your sensitive cryptocurrency operations are protected from eavesdropping and tampering during NFC communication.

### Satochip Commands (Hardware Wallet)

#### Setup and Initialization

##### `cardSetup(byte pinTries, byte[] pin)`
Performs initial card setup with default parameters.

**Parameters:**
- `pinTries`: Number of PIN retry attempts
- `pin`: Initial PIN

**Returns:** `APDUResponse`

##### `cardBip32ImportSeed(byte[] seed)`
Imports a BIP32 master seed into the card. This master seed can be obtained from a BIP39 mnemonic using PBKDF2 derivation
as described in the [BIP39 specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed).

**Parameters:**
- `seed`: Master seed (typically 32-64 bytes)

**Returns:** `APDUResponse`

```java
byte[] seed = new byte[32]; // Your seed data
APDUResponse response = commandSet.cardBip32ImportSeed(seed);
```

##### `cardResetSeed(byte[] pin, byte[] challengeResponse)`
Resets the current seed (requires PIN and optional 2FA).

**Parameters:**
- `pin`: Current PIN
- `challengeResponse`: Optional 2FA challenge response (can be null)

**Returns:** `APDUResponse`

#### Key Derivation and Management

##### `cardBip32GetExtendedKey(String path)`
Derives an extended key for the given BIP32 path.

**Parameters:**
- `path`: BIP32 derivation path (e.g., "m/44'/0'/0'/0/0")

**Returns:** `byte[][]` - [0] = public key, [1] = chain code  
**Throws:** `Exception` for invalid paths or derivation errors

```java
byte[][] extendedKey = commandSet.cardBip32GetExtendedKey("m/44'/0'/0'/0/0");
byte[] publicKey = extendedKey[0];
byte[] chainCode = extendedKey[1];
```

##### `cardBip32GetXpub(String path, int xtype)`
Gets the extended public key (xpub) for a given path.

**Parameters:**
- `path`: BIP32 derivation path
- `xtype`: Extended key version bytes

**Returns:** `String` - Base58-encoded xpub  
**Throws:** `Exception`

```java
String xpub = commandSet.cardBip32GetXpub("m/44'/0'/0'", 0x0488B21E);
```

##### `cardBip32GetAuthentikey()`
Retrieves the card's authentication key.

**Parameters:** None  
**Returns:** `APDUResponse`

#### Transaction Signing

##### `cardSignTransactionHash(byte keyNumber, byte[] txHash, byte[] challengeResponse)`
Signs a transaction hash.

**Parameters:**
- `keyNumber`: Key slot number (typically 0xFF for current key)
- `txHash`: 32-byte hash
- `challengeResponse`: Optional 2FA response (can be null)

**Returns:** `APDUResponse` containing DER-encoded signature  
**Throws:** `RuntimeException` for invalid parameters

```java
byte[] txHash = ...; // 32-byte hash
APDUResponse response = commandSet.cardSignTransactionHash((byte)0xFF, txHash, null);
byte[] signature = response.getData();
```

#### Liquid Support

##### `cardBip32GetLiquidMasterBlindingKey()`
Gets the master blinding key for Liquid transactions.

**Parameters:** None  
**Returns:** `byte[]` - Master blinding key  
**Throws:** `Exception`

### Satodime Commands (Bearer Card)

#### Status and Management

##### `satodimeGetStatus()`
Gets the overall status of the Satodime card.

**Parameters:** None  
**Returns:** `APDUResponse`

```java
APDUResponse response = commandSet.satodimeGetStatus();
SatodimeStatus status = commandSet.getSatodimeStatus();
```

##### `satodimeGetKeyslotStatus(int keyNumber)`
Gets the status of a specific key slot.

**Parameters:**
- `keyNumber`: Key slot index

**Returns:** `APDUResponse`

#### Key Operations

##### `satodimeGetPubkey(int keyNumber)`
Retrieves the public key for a key slot.

**Parameters:**
- `keyNumber`: Key slot index

**Returns:** `APDUResponse` containing public key data

##### `satodimeGetPrivkey(int keyNumber)`
Retrieves the private key for a key slot (unseals the card).

**Parameters:**
- `keyNumber`: Key slot index

**Returns:** `APDUResponse` containing private key data  
**Note:** This operation changes the card state

##### `satodimeSealKey(int keyNumber, byte[] entropy)`
Seals a key slot with user-provided entropy.

**Parameters:**
- `keyNumber`: Key slot index
- `entropy`: User entropy (32 bytes)

**Returns:** `APDUResponse`

##### `satodimeUnsealKey(int keyNumber)`
Unseals a key slot, making the private key accessible.

**Parameters:**
- `keyNumber`: Key slot index

**Returns:** `APDUResponse`

##### `satodimeResetKey(int keyNumber)`
Resets a key slot to uninitialized state.

**Parameters:**
- `keyNumber`: Key slot index

**Returns:** `APDUResponse`

#### Key Slot Configuration

##### `satodimeSetKeyslotStatusPart0(int keyNumber, int RFU1, int RFU2, int keyAsset, byte[] keySlip44, byte[] keyContract, byte[] keyTokenId)`
Sets the first part of key slot metadata.

**Parameters:**
- `keyNumber`: Key slot index
- `RFU1`, `RFU2`: Reserved for future use
- `keyAsset`: Asset type identifier
- `keySlip44`: SLIP-44 coin type (4 bytes)
- `keyContract`: Contract address (34 bytes)
- `keyTokenId`: Token ID (34 bytes)

**Returns:** `APDUResponse`

##### `satodimeSetKeyslotStatusPart1(int keyNumber, byte[] keyData)`
Sets the second part of key slot metadata.

**Parameters:**
- `keyNumber`: Key slot index
- `keyData`: Additional key metadata (66 bytes)

**Returns:** `APDUResponse`

#### Ownership Transfer

##### `satodimeInitiateOwnershipTransfer()`
Initiates the transfer of card ownership.

**Parameters:** None  
**Returns:** `APDUResponse`

### Seedkeeper Commands (Backup Solution)

#### Status and Information

##### `seedkeeperGetStatus()`
Gets the status of the Seedkeeper card.

**Parameters:** None  
**Returns:** `SeedkeeperStatus` object

```java
SeedkeeperStatus status = commandSet.seedkeeperGetStatus();
int secretCount = status.getNbSecrets();
int freeMemory = status.getFreeMemory();
```

#### Secret Management

##### `seedkeeperGenerateMasterseed(int seedSize, SeedkeeperExportRights exportRights, String label)`
Generates a random master seed on the card.

**Parameters:**
- `seedSize`: Size in bytes (16-64)
- `exportRights`: Export permissions
- `label`: Human-readable label

**Returns:** `SeedkeeperSecretHeader`  
**Throws:** `Exception`

```java
SeedkeeperSecretHeader header = commandSet.seedkeeperGenerateMasterseed(
    32, 
    SeedkeeperExportRights.EXPORT_PLAINTEXT_ALLOWED, 
    "My Master Seed"
);
```

##### `seedkeeperImportSecret(SeedkeeperSecretObject secretObject)`
Imports a secret into the card.

**Parameters:**
- `secretObject`: Complete secret object with header and data

**Returns:** `SeedkeeperSecretHeader`  
**Throws:** `Exception`

##### `seedkeeperExportSecret(int sid, Integer sidPubKey)`
Exports a secret from the card.

**Parameters:**
- `sid`: Secret ID
- `sidPubKey`: Public key ID for encryption (null for plaintext)

**Returns:** `SeedkeeperSecretObject`  
**Throws:** `Exception`

```java
// Export in plaintext
SeedkeeperSecretObject secret = commandSet.seedkeeperExportSecret(1, null);

// Export encrypted
SeedkeeperSecretObject encrypted = commandSet.seedkeeperExportSecret(1, 2);
```

##### `seedkeeperResetSecret(int sid)`
Deletes a secret from the card.

**Parameters:**
- `sid`: Secret ID

**Returns:** `APDUResponse`  
**Throws:** `APDUException`

##### `seedkeeperListSecretHeaders()`
Lists all secret headers stored on the card.

**Parameters:** None  
**Returns:** `List<SeedkeeperSecretHeader>`  
**Throws:** `Exception`

```java
List<SeedkeeperSecretHeader> headers = commandSet.seedkeeperListSecretHeaders();
for (SeedkeeperSecretHeader header : headers) {
    System.out.println("Secret: " + header.label + ", ID: " + header.sid);
}
```

#### Advanced Secret Operations

##### `seedkeeperGenerateRandomSecret(SeedkeeperSecretType type, byte subtype, byte size, boolean saveEntropy, byte[] entropy, SeedkeeperExportRights exportRights, String label)`
Generates a random secret with specific parameters.

**Parameters:**
- `type`: Type of secret (MASTERSEED, BIP39_MNEMONIC, etc.)
- `subtype`: Subtype identifier
- `size`: Size in bytes
- `saveEntropy`: Whether to save the entropy separately
- `entropy`: Additional entropy
- `exportRights`: Export permissions
- `label`: Human-readable label

**Returns:** `List<SeedkeeperSecretHeader>`  
**Throws:** `Exception`

##### `seedkeeperPrintLogs(Boolean printAll)`
Retrieves operation logs from the card.

**Parameters:**
- `printAll`: Whether to retrieve all logs

**Returns:** `List<SeedkeeperLog>`  
**Throws:** `Exception`

### Utility Commands

#### Card Management

##### `getCardLabel()`
Gets the card's custom label.

**Parameters:** None  
**Returns:** `String` - Card label

##### `setCardLabel(String label)`
Sets a custom label for the card.

**Parameters:**
- `label`: New label string

**Returns:** `Boolean` - Success status

#### PKI and Certificates

##### `cardExportPersoCertificate()`
Exports the personalization certificate.

**Parameters:** None  
**Returns:** `String` - PEM-formatted certificate  
**Throws:** `APDUException`

##### `cardVerifyAuthenticity()`
Verify the authenticity of the card, using the unique certificate loaded on each card.

**Parameters:** None  
**Returns:** `String[]` - [status, CA cert, SubCA cert, device cert, error message]

```java
String[] result = commandSet.cardVerifyAuthenticity();
String status = result[0]; // "OK" or "FAIL"
if ("FAIL".equals(status)) {
    String error = result[4];
    // Handle verification failure
}
```

## Exception Handling

### Common Exceptions

- **`WrongPINException`**: Wrong PIN with retry count
- **`WrongPINLegacyException`**: Legacy wrong PIN format
- **`BlockedPINException`**: PIN blocked after maximum attempts
- **`ResetToFactoryException`**: Card has been reset to factory state
- **`APDUException`**: General APDU communication error

### Exception Handling Pattern

```java
try {
    commandSet.cardVerifyPIN(pin);
    // Continue with operations
} catch (WrongPINException e) {
    int remaining = e.getRetryAttempts();
    showError("Wrong PIN. " + remaining + " attempts remaining.");
} catch (BlockedPINException e) {
    showError("PIN blocked. Please use PUK to unblock.");
} catch (APDUException e) {
    showError("Communication error: " + e.getMessage());
}
```




