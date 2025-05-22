## Status Word (SW) Reference

All APDU responses include a 2-byte Status Word (SW) that indicates the result of the command.
Here's a comprehensive list of status codes returned by Satochip, Satodime, and Seedkeeper applets:

### Success Codes

| Code | Name | Description |
|------|------|-------------|
| `0x9000` | `SW_OK` | Command executed successfully |

### Standard ISO7816 Error Codes

| Code | Name | Description |
|------|------|-------------|
| `0x6982` | `SW_SECURITY_CONDITION_NOT_SATISFIED` | Security condition not satisfied (authentication required) |
| `0x6983` | `SW_AUTHENTICATION_METHOD_BLOCKED` | Authentication method blocked (PIN blocked) |
| `0x6985` | `SW_CONDITIONS_OF_USE_NOT_SATISFIED` | Conditions of use not satisfied (applet may already be installed) |
| `0x6A88` | `SW_REFERENCED_DATA_NOT_FOUND` | Referenced data not found |
| `0x6283` | `SW_CARD_LOCKED` | Card is locked |

### PIN/Authentication Related Codes

| Code | Name | Description |
|------|------|-------------|
| `0x63C0-0x63CF` | `SW_WRONG_PIN_MASK` | Wrong PIN (last nibble = remaining attempts) |
| `0x9C02` | `SW_WRONG_PIN_LEGACY` | Wrong PIN (legacy format, no retry count) |
| `0x9C0C` | `SW_BLOCKED_PIN` | PIN is blocked after maximum failed attempts |

### Setup and Initialization Codes

| Code | Name | Description |
|------|------|-------------|
| `0x9C04` | `SW_SETUP_NOT_DONE` | Card setup has not been completed |
| `0x9C07` | `SW_SETUP_ALREADY_DONE` | Card setup has already been completed |

### Operation and Parameter Codes

| Code | Name | Description |
|------|------|-------------|
| `0x9C01` | `SW_NO_MEMORY_LEFT` | Insufficient memory available on card |
| `0x9C03` | `SW_OPERATION_NOT_ALLOWED` | Operation not allowed in current circumstances |
| `0x9C05` | `SW_UNSUPPORTED_FEATURE` | Requested feature is not supported |
| `0x9C06` | `SW_UNAUTHORIZED` | Operation not authorized (PIN verification required) |
| `0x9C09` | `SW_INCORRECT_ALG` | Algorithm specified is incorrect |
| `0x9C0B` | `SW_SIGNATURE_INVALID` | Signature verification failed |
| `0x9C0E` | `SW_BIP32_DERIVATION_ERROR` | Error during BIP32 key derivation |
| `0x9C0F` | `SW_INVALID_PARAMETER` | Invalid input parameter provided |
| `0x9C10` | `SW_INCORRECT_P1` | Incorrect P1 parameter in APDU |
| `0x9C11` | `SW_INCORRECT_P2` | Incorrect P2 parameter in APDU |
| `0x9C13` | `SW_INCORRECT_INITIALIZATION` | Incorrect method initialization |

### BIP32 and Key Management Codes

| Code | Name | Description |
|------|------|-------------|
| `0x9C14` | `SW_BIP32_UNINITIALIZED_SEED` | BIP32 seed is not initialized |
| `0x9C15` | `SW_INCORRECT_TXHASH` | Transaction hash is incorrect |
| `0x9C17` | `SW_BIP32_INITIALIZED_SEED` | BIP32 seed is already initialized |
| `0x9C1A` | `SW_ECKEYS_INITIALIZED_KEY` | EC keys are already initialized |

### 2FA (Two-Factor Authentication) Codes

| Code | Name | Description |
|------|------|-------------|
| `0x9C18` | `SW_2FA_INITIALIZED_KEY` | 2FA key is already initialized |
| `0x9C19` | `SW_2FA_UNINITIALIZED_KEY` | 2FA key is not initialized |

### HMAC Related Codes

| Code | Name | Description |
|------|------|-------------|
| `0x9C1E` | `SW_HMAC_UNSUPPORTED_KEYSIZE` | HMAC key size not supported |
| `0x9C1F` | `SW_HMAC_UNSUPPORTED_MSGSIZE` | HMAC message size not supported |

### Secure Channel Codes

| Code | Name | Description |
|------|------|-------------|
| `0x9C20` | `SW_SECURE_CHANNEL_REQUIRED` | Secure channel is required for this operation |
| `0x9C21` | `SW_SECURE_CHANNEL_UNINITIALIZED` | Secure channel is not initialized |
| `0x9C22` | `SW_SECURE_CHANNEL_WRONG_IV` | Incorrect initialization vector in secure channel |
| `0x9C23` | `SW_SECURE_CHANNEL_WRONG_MAC` | Incorrect MAC in secure channel |

### Deprecated Instructions

| Code | Name | Description |
|------|------|-------------|
| `0x9C26` | `SW_INS_DEPRECATED` | Instruction has been deprecated |

### Seedkeeper Specific Codes

| Code | Name | Description |
|------|------|-------------|
| `0x9C30` | `SW_LOCK_ERROR` | Lock error in Seedkeeper |
| `0x9C31` | `SW_EXPORT_NOT_ALLOWED` | Export operation not allowed |
| `0x9C32` | `SW_IMPORTED_DATA_TOO_LONG` | Imported secret data is too long |
| `0x9C33` | `SW_SECURE_IMPORT_WRONG_MAC` | Wrong HMAC during secure import |
| `0x9C34` | `SW_SECURE_IMPORT_WRONG_FINGERPRINT` | Wrong fingerprint during secure import |
| `0x9C35` | `SW_SECURE_IMPORT_NO_TRUSTEDPUBKEY` | No trusted public key for secure import |
| `0x9C36` | `SW_USAGE_NOT_ALLOWED` | Secret usage not allowed |
| `0x9C38` | `SW_WRONG_SECRET_TYPE` | Wrong secret type specified |

### PKI (Public Key Infrastructure) Codes

| Code | Name | Description |
|------|------|-------------|
| `0x9C40` | `SW_PKI_ALREADY_LOCKED` | PKI is already locked |

### Special Codes

| Code | Name | Description |
|------|------|-------------|
| `0xFF00` | `SW_RESET_TO_FACTORY` | Card has been reset to factory settings |
| `0x9CFF` | `SW_INTERNAL_ERROR` | Internal error (for debugging) |
| `0x9FFF` | `SW_DEBUG_FLAG` | Debug flag (for debugging purposes) |
