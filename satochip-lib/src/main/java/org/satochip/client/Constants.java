package org.satochip.client;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.Collections;

public final class Constants {
  
    // Prevents instanciation of class
    private Constants() {}

    /****************************************
    * Instruction codes *
    ****************************************/
    public final static byte CLA =  (byte)0xB0;
    // Applet initialization
    public final static byte INS_SETUP = (byte) 0x2A;
    // Keys' use and management
    public final static byte INS_IMPORT_KEY = (byte) 0x32;
    public final static byte INS_RESET_KEY = (byte) 0x33;
    public final static byte INS_GET_PUBLIC_FROM_PRIVATE= (byte)0x35;
    // External authentication
    public final static byte INS_CREATE_PIN = (byte) 0x40; //TODO: remove?
    public final static byte INS_VERIFY_PIN = (byte) 0x42;
    public final static byte INS_CHANGE_PIN = (byte) 0x44;
    public final static byte INS_UNBLOCK_PIN = (byte) 0x46;
    public final static byte INS_LOGOUT_ALL = (byte) 0x60;
    // Status information
    public final static byte INS_LIST_PINS = (byte) 0x48;
    public final static byte INS_GET_STATUS = (byte) 0x3C;
    public final static byte INS_CARD_LABEL = (byte) 0x3D;
    // HD wallet
    public final static byte INS_BIP32_IMPORT_SEED= (byte) 0x6C;
    public final static byte INS_BIP32_RESET_SEED= (byte) 0x77;
    public final static byte INS_BIP32_GET_AUTHENTIKEY= (byte) 0x73;
    public final static byte INS_BIP32_SET_AUTHENTIKEY_PUBKEY= (byte)0x75;
    public final static byte INS_BIP32_GET_EXTENDED_KEY= (byte) 0x6D;
    public final static byte INS_BIP32_SET_EXTENDED_PUBKEY= (byte) 0x74;
    public final static byte INS_SIGN_MESSAGE= (byte) 0x6E;
    public final static byte INS_SIGN_SHORT_MESSAGE= (byte) 0x72;
    public final static byte INS_SIGN_TRANSACTION= (byte) 0x6F;
    public final static byte INS_PARSE_TRANSACTION = (byte) 0x71;
    public final static byte INS_CRYPT_TRANSACTION_2FA = (byte) 0x76;
    public final static byte INS_SET_2FA_KEY = (byte) 0x79;    
    public final static byte INS_RESET_2FA_KEY = (byte) 0x78;
    public final static byte INS_SIGN_TRANSACTION_HASH= (byte) 0x7A;
    // secure channel
    public final static byte INS_INIT_SECURE_CHANNEL = (byte) 0x81;
    public final static byte INS_PROCESS_SECURE_CHANNEL = (byte) 0x82;
    // secure import from SeedKeeper
    public final static byte INS_IMPORT_ENCRYPTED_SECRET = (byte) 0xAC;
    public final static byte INS_IMPORT_TRUSTED_PUBKEY = (byte) 0xAA;
    public final static byte INS_EXPORT_TRUSTED_PUBKEY = (byte) 0xAB;
    public final static byte INS_EXPORT_AUTHENTIKEY= (byte) 0xAD;
    // Personalization PKI support
    public final static byte INS_IMPORT_PKI_CERTIFICATE = (byte) 0x92;
    public final static byte INS_EXPORT_PKI_CERTIFICATE = (byte) 0x93;
    public final static byte INS_SIGN_PKI_CSR = (byte) 0x94;
    public final static byte INS_EXPORT_PKI_PUBKEY = (byte) 0x98;
    public final static byte INS_LOCK_PKI = (byte) 0x99;
    public final static byte INS_CHALLENGE_RESPONSE_PKI= (byte) 0x9A;
    // reset to factory settings
    public final static byte INS_RESET_TO_FACTORY = (byte) 0xFF;

    // Satodime
    public final static byte INS_GET_SATODIME_STATUS= (byte)0x50;
    public final static byte INS_GET_SATODIME_KEYSLOT_STATUS= (byte)0x51;
    public final static byte INS_SET_SATODIME_KEYSLOT_STATUS= (byte)0x52;
    public final static byte INS_GET_SATODIME_PUBKEY= (byte)0x55; // do not change state
    public final static byte INS_GET_SATODIME_PRIVKEY= (byte)0x56;// do not change state
    public final static byte INS_SEAL_SATODIME_KEY= (byte)0x57; // change key state from uninitialized to sealed
    public final static byte INS_UNSEAL_SATODIME_KEY= (byte)0x58; // change key state from sealed to unsealed
    public final static byte INS_RESET_SATODIME_KEY= (byte)0x59; // change key state from unsealed to uninitialized
    public final static byte INS_INITIATE_SATODIME_TRANSFER= (byte)0x5A;

    // Seedkeeper

    public final static byte INS_GET_SEEDKEEPER_STATUS = (byte)0xA7;
    public final static byte INS_GENERATE_SEEDKEEPER_MASTER_SEED = (byte)0xA0;
    public final static byte INS_GENERATE_SEEDKEEPER_RANDOM_SECRET = (byte)0xA3;
    public final static byte INS_GENERATE_SEEDKEEPER_2FA_SECRET = (byte)0xAE;
    public final static byte INS_IMPORT_SEEDKEEPER_SECRET = (byte)0xA1;
    public final static byte INS_EXPORT_SEEDKEEPER_SECRET = (byte)0xA2;
    public final static byte INS_EXPORT_SEEDKEEPER_SECRET_TO_SATOCHIP = (byte)0xA8;
    public final static byte INS_RESET_SEEDKEEPER_SECRET = (byte)0xA5;
    public final static byte INS_LIST_SEEDKEEPER_SECRET_HEADERS = (byte)0xA6;
    public final static byte INS_PRINT_SEEDKEEPER_LOGS = (byte)0xA9;
    public final static byte INS_DERIVE_SEEDKEEPER_MASTER_PASSWORD = (byte)0xAF;



    /****************************************
    *          Error codes                 *
    ****************************************/

    /** Entered PIN is not correct */
    public final static short SW_PIN_FAILED = (short)0x63C0;// includes number of tries remaining
    ///** DEPRECATED - Entered PIN is not correct */
    //public final static short SW_AUTH_FAILED = (short) 0x9C02;
    /** Required operation is not allowed in actual circumstances */
    public final static short SW_OPERATION_NOT_ALLOWED = (short) 0x9C03;
    /** Required setup is not not done */
    public final static short SW_SETUP_NOT_DONE = (short) 0x9C04;
    /** Required setup is already done */
    public final static short SW_SETUP_ALREADY_DONE = (short) 0x9C07;
    /** Required feature is not (yet) supported */
    final static short SW_UNSUPPORTED_FEATURE = (short) 0x9C05;
    /** Required operation was not authorized because of a lack of privileges */
    public final static short SW_UNAUTHORIZED = (short) 0x9C06;
    /** Algorithm specified is not correct */
    public final static short SW_INCORRECT_ALG = (short) 0x9C09;

    /** There have been memory problems on the card */
    public final static short SW_NO_MEMORY_LEFT = (short) 0x9C01;
    ///** DEPRECATED - Required object is missing */
    //public final static short SW_OBJECT_NOT_FOUND= (short) 0x9C07;

    /** Incorrect P1 parameter */
    public final static short SW_INCORRECT_P1 = (short) 0x9C10;
    /** Incorrect P2 parameter */
    public final static short SW_INCORRECT_P2 = (short) 0x9C11;
    /** Invalid input parameter to command */
    public final static short SW_INVALID_PARAMETER = (short) 0x9C0F;

    /** Eckeys initialized */
    public final static short SW_ECKEYS_INITIALIZED_KEY = (short) 0x9C1A;

    /** Verify operation detected an invalid signature */
    public final static short SW_SIGNATURE_INVALID = (short) 0x9C0B;
    /** Operation has been blocked for security reason */
    public final static short SW_IDENTITY_BLOCKED = (short) 0x9C0C;
    /** For debugging purposes */
    public final static short SW_INTERNAL_ERROR = (short) 0x9CFF;
    /** Very low probability error */
    public final static short SW_BIP32_DERIVATION_ERROR = (short) 0x9C0E;
    /** Incorrect initialization of method */
    public final static short SW_INCORRECT_INITIALIZATION = (short) 0x9C13;
    /** Bip32 seed is not initialized*/
    public final static short SW_BIP32_UNINITIALIZED_SEED = (short) 0x9C14;
    /** Bip32 seed is already initialized (must be reset before change)*/
    public final static short SW_BIP32_INITIALIZED_SEED = (short) 0x9C17;
    //** DEPRECATED - Bip32 authentikey pubkey is not initialized*/
    //public final static short SW_BIP32_UNINITIALIZED_AUTHENTIKEY_PUBKEY= (short) 0x9C16;
    /** Incorrect transaction hash */
    public final static short SW_INCORRECT_TXHASH = (short) 0x9C15;

    /** 2FA already initialized*/
    public final static short SW_2FA_INITIALIZED_KEY = (short) 0x9C18;
    /** 2FA uninitialized*/
    public final static short SW_2FA_UNINITIALIZED_KEY = (short) 0x9C19;
      
    /** HMAC errors */
    static final short SW_HMAC_UNSUPPORTED_KEYSIZE = (short) 0x9c1E;
    static final short SW_HMAC_UNSUPPORTED_MSGSIZE = (short) 0x9c1F;

    /** Secure channel */
    public final static short SW_SECURE_CHANNEL_REQUIRED = (short) 0x9C20;
    public final static short SW_SECURE_CHANNEL_UNINITIALIZED = (short) 0x9C21;
    public final static short SW_SECURE_CHANNEL_WRONG_IV= (short) 0x9C22;
    public final static short SW_SECURE_CHANNEL_WRONG_MAC= (short) 0x9C23;

    /** Secret data is too long for import **/
    public final static short SW_IMPORTED_DATA_TOO_LONG = (short) 0x9C32;
    /** Wrong HMAC when importing Secret through Secure import **/
    public final static short SW_SECURE_IMPORT_WRONG_MAC = (short) 0x9C33;
    /** Wrong Fingerprint when importing Secret through Secure import **/
    public final static short SW_SECURE_IMPORT_WRONG_FINGERPRINT = (short) 0x9C34;
    /** No Trusted Pubkey when importing Secret through Secure import **/
    public final static short SW_SECURE_IMPORT_NO_TRUSTEDPUBKEY = (short) 0x9C35;

    /** PKI perso error */
    public final static short SW_PKI_ALREADY_LOCKED = (short) 0x9C40;
    /** CARD HAS BEEN RESET TO FACTORY */
    public final static short SW_RESET_TO_FACTORY = (short) 0xFF00;
    /** For instructions that have been deprecated*/
    public final static short SW_INS_DEPRECATED = (short) 0x9C26;
    /** For debugging purposes 2 */
    public final static short SW_DEBUG_FLAG = (short) 0x9FFF;

    /****************************************
    *           Other  constants            *
    ****************************************/

    // KeyBlob Encoding in Key Blobs
    public final static byte BLOB_ENC_PLAIN = (byte) 0x00;

    // Cipher Operations admitted in ComputeCrypt()
    public final static byte OP_INIT = (byte) 0x01;
    public final static byte OP_PROCESS = (byte) 0x02;
    public final static byte OP_FINALIZE = (byte) 0x03;

    // JC API 2.2.2 does not define these constants:
    public final static byte ALG_ECDSA_SHA_256= (byte) 33;
    public final static byte ALG_EC_SVDP_DH_PLAIN= (byte) 3; //https://javacard.kenai.com/javadocs/connected/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN
    public final static byte ALG_EC_SVDP_DH_PLAIN_XY= (byte) 6; //https://docs.oracle.com/javacard/3.0.5/api/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN_XY
    public final static short LENGTH_EC_FP_256= (short) 256;

    /****************************************
     *               Seedkeeper             *
     ****************************************/
    public final static byte LOCK_ERROR = (byte)0x9C30;
    public final static byte EXPORT_NOT_ALLOWED = (byte)0x9C31;
    public final static byte USAGE_NOT_ALLOWED = (byte)0x9C36;
    public final static byte WRONG_SECRET_TYPE = (byte)0x9C38;

    /****************************************
    *               Satodime                   *
    ****************************************/

    public final static short SIZE_ECPRIVKEY= (short)32;
    public final static short SIZE_ECPUBKEY= (short)65;
    public final static short SIZE_ECCOORDX= (short)32;
    public final static short SIZE_ENTROPY= (short)32;

    public final static byte SIZE_UNLOCK_SECRET=20;
    public final static byte SIZE_UNLOCK_COUNTER=4;

    public final static byte STATE_UNINITIALIZED=0;
    public final static byte STATE_SEALED=1;
    public final static byte STATE_UNSEALED=2;
    public final static String[] STATE_STRING_ARRAY= {"Uninitialized", "Sealed", "Unsealed"};

    public final static byte SIZE_SLIP44=4;
    public final static byte SIZE_CONTRACT=2+32;
    public final static byte SIZE_TOKENID=2+32;
    public final static byte SIZE_DATA=2+64;
    public final static byte SIZE_UNLOCK_CODE=20;
    //public final static short SIZE_KEY_METADATA= (short)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + 3 + SIZE_SLIP44 + SIZE_CONTRACT + SIZE_TOKENID + SIZE_DATA);
    public final static short SIZE_KEY_METADATA_0= (short)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + 3 + SIZE_SLIP44 + SIZE_CONTRACT + SIZE_TOKENID);
    public final static short SIZE_KEY_METADATA_1= (short)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + SIZE_DATA);

    // map asset name => code
    public static final Map<String, Integer> MAP_CODE_BY_ASSET;
    static {
        Map<String, Integer> tmpmap= new HashMap<String, Integer>();
        tmpmap.put("Undefined", 0x00);
        tmpmap.put("Coin", 0x01);
        tmpmap.put("Token", 0x10);
        tmpmap.put("ERC20", 0x11);
        tmpmap.put("BEP20", 0x12);
        tmpmap.put("NFT", 0x40);
        tmpmap.put("ERC721", 0x41);
        tmpmap.put("BEP721", 0x42);
        tmpmap.put("Other", 0xFF);
        MAP_CODE_BY_ASSET = Collections.unmodifiableMap(tmpmap);
    }
    // map code => asset name
    public static final Map<Integer, String> MAP_ASSET_BY_CODE;
    static {
        Map<Integer, String> tmpmap= new HashMap<Integer, String>();
        tmpmap.put(0x00, "Undefined");
        tmpmap.put(0x01, "Coin");
        tmpmap.put(0x10, "Token");
        tmpmap.put(0x11, "ERC20");
        tmpmap.put(0x12, "BEP20");
        tmpmap.put(0x40, "NFT");
        tmpmap.put(0x41, "ERC721");
        tmpmap.put(0x42, "BEP721");
        tmpmap.put(0xFF, "Other");
        MAP_ASSET_BY_CODE = Collections.unmodifiableMap(tmpmap);
    }    
    
    public static final String[] TOKENS = {"Token", "ERC20", "BEP20"};
    public static final String[] NFTS = {"NFT", "ERC721", "BEP721"};
    public static final Set<String> TOKENSET = new HashSet<>(Arrays.asList(TOKENS));
    public static final Set<String> NFTSET = new HashSet<>(Arrays.asList(NFTS));
    
}
