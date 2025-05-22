# SatochipParser Class Documentation

## Overview

The `SatochipParser` class is the component of the Satochip-Java library that handles parsing and cryptographic 
operations for APDU responses from Satochip, Satodime, and Seedkeeper cards. It provides functionality for:

- Parsing APDU response data
- ECDSA signature verification and public key recovery
- BIP32 path parsing and conversion
- Cryptographic operations using secp256k1 curve
- Certificate format conversion (used to check card authenticity)

## Class Structure

```java
public class SatochipParser {
    // Cryptographic constants
    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    public static final ECDomainParameters CURVE;
    public static final BigInteger HALF_CURVE_ORDER, CURVE_ORDER;
    
    // Utility constants
    public static final String HEXES = "0123456789ABCDEF";
    
    // Internal state
    private byte[] authentikey = null;
}
```

## Core Methods

### BIP32 Path Operations

#### `parseBip32PathToBytes(String bip32path)`
Converts a BIP32 derivation path string to its byte representation.

**Parameters:**
- `bip32path` (String): BIP32 path (e.g., "m/44'/0'/0'/0/0")

**Returns:**
- `Bip32Path`: Object containing depth and byte representation

**Throws:**
- `Exception`: For invalid path format

**Example:**
```java
SatochipParser parser = new SatochipParser();
Bip32Path path = parser.parseBip32PathToBytes("m/44'/0'/0'/0/0");

int depth = path.getDepth();        // 5
byte[] pathBytes = path.getBytes(); // [0x8000002C, 0x80000000, 0x80000000, 0x00000000, 0x00000000]
```

**Path Format Rules:**
- Starts with "m" for master key (optional)
- Components separated by "/"
- Hardened derivation indicated by "'" or "h" suffix
- Maximum 10 components supported by Satochip.
- Each component is a 32-bit integer converted to 4 bytes for the card.

### APDU Response Parsing

#### `parseInitiateSecureChannel(APDUResponse rapdu)`
Parses the response from an INITIALIZE_SECURE_CHANNEL command.

**Parameters:**
- `rapdu` (APDUResponse): Response from secure channel initialization

**Returns:**
- `byte[]`: Card's public key for ECDH key agreement

**Response Format:**
```
[coordx_size(2b) | coordx | sig1_size(2b) | sig1 | sig2_size(2b) | sig2]
```

**Example:**
```java
APDUResponse response = commandSet.cardInitiateSecureChannel();
byte[] cardPubkey = parser.parseInitiateSecureChannel(response);
```

#### `parseInitiateSecureChannelGetPossibleAuthentikeys(APDUResponse rapdu)`
Recovers possible authentication keys from secure channel initialization.

**Parameters:**
- `rapdu` (APDUResponse): Response from secure channel initialization

**Returns:**
- `List<byte[]>`: List of possible authentication public keys

**Purpose:**
- Determines which authentication key the card is using
- Supports both legacy (multiple possibilities) and modern (single key) formats

#### `parseBip32GetAuthentikey(APDUResponse rapdu)`
Parses response from BIP32_GET_AUTHENTIKEY command.

**Parameters:**
- `rapdu` (APDUResponse): Response containing authentikey data

**Returns:**
- `byte[]`: 65-byte uncompressed public key

**Response Format:**
```
[coordx_size(2b) | coordx | sig_size(2b) | sig]
```

#### `parseBip32GetExtendedKey(APDUResponse rapdu)`
Parses response from BIP32_GET_EXTENDED_KEY command.

**Parameters:**
- `rapdu` (APDUResponse): Response containing extended key data

**Returns:**
- `byte[][]`: [0] = public key (65 bytes), [1] = chain code (32 bytes)

**Response Format:**
```
[chaincode(32b) | coordx_size(2b) | coordx | sig_size(2b) | sig | sig2_size(2b) | sig2]
```

**Example:**
```java
APDUResponse response = commandSet.cardBip32GetExtendedKey("m/44'/0'/0'/0/0");
byte[][] extendedKey = parser.parseBip32GetExtendedKey(response);
byte[] publicKey = extendedKey[0];  // 65-byte uncompressed public key
byte[] chainCode = extendedKey[1];  // 32-byte chain code
```

### Cryptographic Operations

#### `recoverPubkey(byte[] msg, byte[] sig, byte[] coordx)`
Recovers a public key from a message signature using ECDSA key recovery.

**Parameters:**
- `msg` (byte[]): Original message that was signed
- `sig` (byte[]): DER-encoded ECDSA signature
- `coordx` (byte[]): X-coordinate of the public key (32 bytes)

**Returns:**
- `byte[]`: 65-byte uncompressed public key, or null if recovery fails

**Algorithm:**
1. Hash the message with SHA256
2. Convert DER signature to compact format
3. Try all 4 possible recovery IDs
4. Return the key that matches the given X-coordinate

**Example:**
```java
byte[] message = "Hello World".getBytes();
byte[] signature = ...; // DER-encoded signature
byte[] xCoord = ...; // X-coordinate from card response

byte[] recoveredKey = parser.recoverPubkey(message, signature, xCoord);
```

#### `recoverPossiblePubkeys(byte[] msg, byte[] sig)`
Recovers all possible public keys from a signature (when X-coordinate is unknown).

**Parameters:**
- `msg` (byte[]): Original message
- `sig` (byte[]): DER-encoded signature

**Returns:**
- `List<byte[]>`: List of up to 4 possible public keys

#### `verifySig(byte[] msg, byte[] dersig, byte[] pub)`
Verifies an ECDSA signature against a message and public key.

**Parameters:**
- `msg` (byte[]): Original message
- `dersig` (byte[]): DER-encoded signature
- `pub` (byte[]): 65-byte uncompressed public key

**Returns:**
- `boolean`: True if signature is valid

**Example:**
```java
boolean isValid = parser.verifySig(message, signature, publicKey);
if (isValid) {
    System.out.println("Signature verified successfully");
}
```

### Signature Format Conversion

#### `parseToCompactSignature(byte[] sigIn)`
Converts DER-encoded signature to compact format.

**Parameters:**
- `sigIn` (byte[]): DER-encoded signature

**Returns:**
- `byte[]`: 64-byte compact signature (32-byte r + 32-byte s)

**DER Format:**
```
30 <length> 02 <r_length> <r_value> 02 <s_length> <s_value>
```

**Compact Format:**
```
<r_value(32b)> <s_value(32b)>
```

#### `decodeFromDER(byte[] bytes)`
Decodes DER-encoded signature to BigInteger array with BIP62 enforcement.

**Parameters:**
- `bytes` (byte[]): DER-encoded signature

**Returns:**
- `BigInteger[]`: [0] = r value, [1] = s value (canonicalized)

**BIP62 Compliance:**
- Enforces low-S signature format
- If s > HALF_CURVE_ORDER, converts to CURVE_ORDER - s

### Public Key Operations

#### `compressPubKey(byte[] pubkey)`
Converts uncompressed public key to compressed format.

**Parameters:**
- `pubkey` (byte[]): 65-byte uncompressed key or 33-byte compressed key

**Returns:**
- `byte[]`: 33-byte compressed public key

**Format Conversion:**
- Uncompressed: `04 <x(32b)> <y(32b)>`
- Compressed: `02|03 <x(32b)>` (02 if y is even, 03 if y is odd)

**Example:**
```java
byte[] uncompressed = ...; // 65-byte key starting with 0x04
byte[] compressed = parser.compressPubKey(uncompressed); // 33-byte key
```

### Certificate Operations

#### `convertBytesToStringPem(byte[] certBytes)`
Converts DER-encoded certificate to PEM format.

**Parameters:**
- `certBytes` (byte[]): DER-encoded X.509 certificate

**Returns:**
- `String`: PEM-formatted certificate

**Output Format:**
```
-----BEGIN CERTIFICATE-----
<Base64-encoded certificate data in 64-character lines>
-----END CERTIFICATE-----
```

#### `parseVerifyChallengeResponsePerso(APDUResponse rapdu)`
Parses challenge-response data for personalization verification.

**Parameters:**
- `rapdu` (APDUResponse): Response from challenge-response command

**Returns:**
- `byte[][]`: [0] = challenge from device (32 bytes), [1] = signature

### Utility Methods

#### `toHexString(byte[] raw)` (static)
Converts byte array to hexadecimal string representation.

**Parameters:**
- `raw` (byte[]): Byte array to convert

**Returns:**
- `String`: Hexadecimal string (uppercase, no separators)

**Example:**
```java
byte[] data = {0x01, 0x02, 0xAB, 0xCD};
String hex = SatochipParser.toHexString(data); // "0102ABCD"
```

#### `fromHexString(String hex)` (static)
Converts hexadecimal string to byte array.

**Parameters:**
- `hex` (String): Hexadecimal string (even length required)

**Returns:**
- `byte[]`: Converted byte array

**Throws:**
- `IllegalArgumentException`: If string length is odd

**Example:**
```java
String hex = "0102ABCD";
byte[] data = SatochipParser.fromHexString(hex); // {0x01, 0x02, 0xAB, 0xCD}
```

## Advanced Cryptographic Details

### ECDSA Key Recovery Process

The key recovery process implements the standard ECDSA key recovery algorithm:

1. **Parse signature components**: Extract r and s from DER encoding
2. **Calculate recovery candidates**: For each recovery ID (0-3):
    - Calculate R point from r value and recovery ID
    - Compute Q = r^(-1) * (s*R - e*G) where e is message hash
3. **Verify X-coordinate**: Compare recovered key's X-coordinate with expected
4. **Return matching key**: First key that matches the X-coordinate

### Curve Parameters (secp256k1)

```java
// Curve equation: y² = x³ + 7 (mod p)
static {
    CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
    CURVE = new ECDomainParameters(
        CURVE_PARAMS.getCurve(), 
        CURVE_PARAMS.getG(), 
        CURVE_PARAMS.getN(), 
        CURVE_PARAMS.getH()
    );
    CURVE_ORDER = CURVE_PARAMS.getN();
    HALF_CURVE_ORDER = CURVE_PARAMS.getN().shiftRight(1);
}
```

### Signature Canonicalization (BIP62)

The parser enforces BIP62 low-S signature format:

```java
// Enforce low-S signature
BigInteger s2 = s.getPositiveValue();
if (s2.compareTo(HALF_CURVE_ORDER) > 0) {
    s2 = CURVE_ORDER.subtract(s2);
}
```

## Error Handling

### Common Exceptions

- **`RuntimeException`**: Cryptographic errors, invalid signatures
- **`Exception`**: Invalid BIP32 paths, parsing errors
- **`IllegalArgumentException`**: Invalid input parameters

### Error Scenarios

1. **Invalid signature format**: DER parsing failures
2. **Key recovery failure**: No valid recovery ID found
3. **Invalid BIP32 path**: Malformed path strings
4. **Cryptographic errors**: BouncyCastle library issues

## Usage Patterns

### Basic Parsing Flow
```java
// 1. Create parser
SatochipParser parser = new SatochipParser();

// 2. Parse BIP32 path
Bip32Path path = parser.parseBip32PathToBytes("m/44'/0'/0'/0/0");

// 3. Send command and parse response
APDUResponse response = commandSet.cardBip32GetExtendedKey(path);
byte[][] extendedKey = parser.parseBip32GetExtendedKey(response);

// 4. Verify signature if needed
boolean isValid = parser.verifySig(message, signature, extendedKey[0]);
```

### Secure Channel Initialization
```java
// 1. Initialize secure channel
APDUResponse initResponse = commandSet.cardInitiateSecureChannel();

// 2. Parse card's public key
byte[] cardPubkey = parser.parseInitiateSecureChannel(initResponse);

// 3. Get possible authentication keys
List<byte[]> authKeys = parser.parseInitiateSecureChannelGetPossibleAuthentikeys(initResponse);

// 4. Verify card authenticity
for (byte[] authKey : authKeys) {
    if (parser.verifySig(challengeMessage, cardSignature, authKey)) {
        // Found valid authentication key
        break;
    }
}
```

## Dependencies

### Required Libraries
- **BouncyCastle**: Cryptographic operations (`org.bouncycastle.*`)
- **Standard Java**: Basic utilities and I/O

### BouncyCastle Components Used
- `CustomNamedCurves.getByName("secp256k1")`
- `ECDSASigner` for signature verification
- `SHA256Digest` for message hashing
- `ASN1InputStream` for DER parsing

## Security Considerations

1. **Signature Verification**: Always verify signatures before trusting recovered keys
2. **Input Validation**: Validate all input parameters before processing
3. **Memory Management**: Sensitive data should be cleared after use
4. **Error Handling**: Don't leak sensitive information in error messages
5. **Constant Time**: Some operations should be constant-time to prevent side-channel attacks

## Performance Notes

1. **Caching**: The parser maintains minimal state (only authentikey)
2. **Computation Cost**: ECDSA operations are computationally expensive
3. **Memory Usage**: Temporary objects created during parsing should be garbage collected promptly
4. **Thread Safety**: The parser is not thread-safe due to internal state

## Best Practices

1. **Reuse Parser Instance**: Create one parser per session
2. **Validate Inputs**: Check path formats and data lengths
3. **Handle Exceptions**: Wrap parser calls in try-catch blocks
4. **Verify Signatures**: Always verify cryptographic signatures
5. **Clear Sensitive Data**: Zero out private data when finished

