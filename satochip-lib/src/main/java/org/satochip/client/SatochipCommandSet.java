package org.satochip.client;

//import org.satochip.io.*;
import org.satochip.io.*;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.io.IOException;
import java.lang.ClassLoader;
import java.net.URL;

import java.io.InputStream;
import java.io.SequenceInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.Files; 

import java.security.cert.CertPathValidator;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathParameters;
import java.security.cert.PKIXParameters;
import java.security.KeyStore;
import java.security.KeyStore.TrustedCertificateEntry;

import javax.security.cert.X509Certificate;
import java.security.PublicKey;

import static org.satochip.client.Constants.*;

/**
 * This class is used to send APDU to the applet. Each method corresponds to an APDU as defined in the APPLICATION.md
 * file. Some APDUs map to multiple methods for the sake of convenience since their payload or response require some
 * pre/post processing.
 */
public class SatochipCommandSet {
    
    private final CardChannel apduChannel;
    private SecureChannelSession secureChannel;
    private ApplicationStatus status;
    private boolean needs_secure_channel= false; // TODO:remove (stored in status)

    private SatochipParser parser=null;

    private byte[] pin0=null;
    private byte[] authentikey= null;
    private String authentikeyHex= null;
    private String defaultBip32path= null;


    // Satodime, SeedKeeper or Satochip?
    private String cardType= null;
    private String certPem= null; // PEM certificate of device, if any

    // satodime
    SatodimeStatus satodimeStatus= null;
    //private byte[] unlock_secret= null;
    //private byte[] unlock_counter= null;
    //private SatodimeUnlockSecret satodimeUnlockSecret=null;

    public static final byte[] SATOCHIP_AID = Hex.decode("5361746f43686970"); //SatoChip
    public static final byte[] SEEDKEEPER_AID = Hex.decode("536565644b6565706572"); //SeedKeeper
    public static final byte[] SATODIME_AID = Hex.decode("5361746f44696d65"); //SatoDime 

    public final static byte DERIVE_P1_SOURCE_MASTER = (byte) 0x00;
    public final static byte DERIVE_P1_SOURCE_PARENT = (byte) 0x40;
    public final static byte DERIVE_P1_SOURCE_CURRENT = (byte) 0x80;

    /**
    * Creates a SatochipCommandSet using the given APDU Channel
    * @param apduChannel APDU channel
    */
    public SatochipCommandSet(CardChannel apduChannel) {
        this.apduChannel = apduChannel;
        this.secureChannel = new SecureChannelSession();
        this.parser= new SatochipParser();
        this.satodimeStatus= new SatodimeStatus();
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
    
    public byte[] getSatodimeUnlockSecret(){
        return this.satodimeStatus.getUnlockSecret();
    }
    
    public void setSatodimeUnlockSecret(byte[] unlockSecret){
        this.satodimeStatus.setUnlockSecret(unlockSecret);
    }
    
    /****************************************
    *                AUTHENTIKEY                    *
    ****************************************/
    public byte[] getAuthentikey() {
        if (authentikey == null){
          cardGetAuthentikey();
        }
        return authentikey;
    }
  
    public String getAuthentikeyHex() {
        if (authentikeyHex == null){
            cardGetAuthentikey();
        }
        return authentikeyHex;
    }
  
    public byte[] getBip32Authentikey() {
        if (authentikey == null){
            cardBip32GetAuthentikey();
        }
        return authentikey;
    }
  
    public String getBip32AuthentikeyHex() {
        if (authentikeyHex == null){
            cardBip32GetAuthentikey();
        }
        return authentikeyHex;
    }
  
  
  
    public SatochipParser getParser() {
        return parser;
    }
  
    public void setDefaultBip32path(String bip32path) {
        defaultBip32path= bip32path;
    }
  
    /**
    * Set the SecureChannel object
    * @param secureChannel secure channel
    */
    protected void setSecureChannel(SecureChannelSession secureChannel) {
        this.secureChannel = secureChannel;
    }
    
    public APDUResponse cardTransmit(APDUCommand plainApdu) {
        
        // we try to transmit the APDU until we receive the answer or we receive an unrecoverable error
        boolean isApduTransmitted= false;
        do{
            try{
                byte[] apduBytes= plainApdu.serialize();
                byte ins= apduBytes[1];
                boolean isEncrypted=false;

                // check if status available
                if (status == null){
                    APDUCommand statusCapdu = new APDUCommand(0xB0, INS_GET_STATUS, 0x00, 0x00, new byte[0]);
                    APDUResponse statusRapdu = apduChannel.send(statusCapdu);
                    status= new ApplicationStatus(statusRapdu);
                    System.out.println("Status cardGetStatus:"+ status.toString());
                }

                APDUCommand capdu=null;
                if (status.needsSecureChannel() && (ins!=0xA4) &&  (ins!=0x81) && (ins!=0x82) && (ins!=INS_GET_STATUS)){
                  
                    if (!secureChannel.initializedSecureChannel()){
                        // get card's public key
                        APDUResponse secChannelRapdu= cardInitiateSecureChannel();
                        byte[] pubkey= parser.parseInitiateSecureChannel(secChannelRapdu);
                        // setup secure channel
                        secureChannel.initiateSecureChannel(pubkey);
                        System.out.println("secure Channel initiated!");
                    }
                    // encrypt apdu
                    System.out.println("Capdu before encryption:"+ plainApdu.toHexString());
                    capdu= secureChannel.encrypt_secure_channel(plainApdu);
                    isEncrypted=true;
                    System.out.println("Capdu encrypted:"+ capdu.toHexString());
                }
                else {
                    // plain adpu
                    capdu= plainApdu;
                }

                APDUResponse rapdu =  apduChannel.send(capdu);
                int sw12= rapdu.getSw() ;

                // check answer
                if (sw12==0x9000){ // ok!
                    if (isEncrypted){
                        // decrypt 
                        System.out.println("Rapdu encrypted:"+ rapdu.toHexString());
                        rapdu = secureChannel.decrypt_secure_channel(rapdu);
                        System.out.println("Rapdu decrypted:"+ rapdu.toHexString());
                    }
                    isApduTransmitted= true; // leave loop
                    return  rapdu;
                } 
                // PIN authentication is required
                else if (sw12==0x9C06){
                    cardVerifyPIN(); 
                }
                // SecureChannel is not initialized
                else if (sw12==0x9C21){
                    secureChannel.resetSecureChannel(); 
                }
                else {
                    // cannot resolve issue at this point
                    isApduTransmitted= true; // leave loop
                    return rapdu;
                }

            } catch(Exception e) {
                System.out.println("Exception in cardTransmit: "+ e);
                return new APDUResponse(new byte[0], (byte)0x00, (byte)0x00); // return empty APDUResponse
            }
          
        } while(!isApduTransmitted);
        
        return new APDUResponse(new byte[0], (byte)0x00, (byte)0x00); // should not happen
    }
    
    public void cardDisconnect(){
        secureChannel.resetSecureChannel();
        status= null;
        pin0= null;
    }
    
    /**
    * Selects a Satochip/Satodime/SeedKeeper instance. The applet is assumed to have been installed with its default AID. 
    *
    * @return the raw card response
    * @throws IOException communication error
    */
    public APDUResponse cardSelect() throws IOException {

        APDUResponse rapdu= cardSelect("satochip");
        if (rapdu.getSw()!=0x9000){
            rapdu= cardSelect("seedkeeper");
            if (rapdu.getSw()!=0x9000){
                rapdu= cardSelect("satodime");
                if (rapdu.getSw()!=0x9000){
                    this.cardType= "unknown";
                    System.out.println("Satochip-java: CardSelect: could not select a known applet");
                }
            } 
        }
    
        return rapdu;
    }
  
    public APDUResponse cardSelect(String cardType) throws IOException {
      
        APDUCommand selectApplet; 
        if (cardType.equals("satochip")){
            selectApplet= new APDUCommand(0x00, 0xA4, 0x04, 0x00, SATOCHIP_AID); 
        } 
        else if (cardType.equals("seedkeeper")){
            selectApplet= new APDUCommand(0x00, 0xA4, 0x04, 0x00, SEEDKEEPER_AID); 
        }
        else{
            selectApplet= new APDUCommand(0x00, 0xA4, 0x04, 0x00, SATODIME_AID); 
        }

        System.out.println("C-APDU cardSelect:"+ selectApplet.toHexString());
        APDUResponse respApdu =  apduChannel.send(selectApplet);
        System.out.println("R-APDU cardSelect:"+ respApdu.toHexString());
        
        if (respApdu.getSw()==0x9000){
            this.cardType= cardType;
            System.out.println("Satochip-java: CardSelect: found a " + this.cardType);
        }
        return respApdu;
    }
  
    public APDUResponse cardGetStatus() {
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_STATUS, 0x00, 0x00, new byte[0]);
        
        System.out.println("C-APDU cardGetStatus:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardGetStatus:"+ respApdu.toHexString());
    
        status= new ApplicationStatus(respApdu);
        needs_secure_channel= status.needsSecureChannel(); //todo: remove
        System.out.println("Status from cardGetStatus:"+ status.toString());
    
        return respApdu;
    }
    
    public APDUResponse cardInitiateSecureChannel() throws IOException{
    
        byte[] pubkey= secureChannel.getPublicKey();
    
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_INIT_SECURE_CHANNEL, 0x00, 0x00, pubkey);
        
        System.out.println("C-APDU cardInitiateSecureChannel:"+ plainApdu.toHexString());
        APDUResponse respApdu = apduChannel.send(plainApdu);
        System.out.println("R-APDU cardInitiateSecureChannel:"+ respApdu.toHexString());
    
        return respApdu;
    }
    
    // only valid for v0.12 and higher
    public APDUResponse cardGetAuthentikey() {

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_EXPORT_AUTHENTIKEY, 0x00, 0x00, new byte[0]);
        System.out.println("C-APDU cardExportAuthentikey:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardExportAuthentikey:"+ respApdu.toHexString());
        
        // parse and recover pubkey
        authentikey= parser.parseBip32GetAuthentikey(respApdu);
        authentikeyHex= parser.toHexString(authentikey);
        System.out.println("Authentikey from cardExportAuthentikey:"+ authentikeyHex);
        
        return respApdu;
    }
    
    public APDUResponse cardBip32GetAuthentikey() {

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_BIP32_GET_AUTHENTIKEY, 0x00, 0x00, new byte[0]);
        System.out.println("C-APDU cardBip32GetAuthentikey:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardBip32GetAuthentikey:"+ respApdu.toHexString());
        
        // parse and recover pubkey
        authentikey= parser.parseBip32GetAuthentikey(respApdu);
        authentikeyHex= parser.toHexString(authentikey);
        System.out.println("Authentikey from cardBip32GetAuthentikey:"+ authentikeyHex);
        
        return respApdu;
    }  
    
    public APDUResponse cardExportPkiPubkey() {

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_EXPORT_PKI_PUBKEY, 0x00, 0x00, new byte[0]);
        System.out.println("C-APDU cardExportPkiPubkey:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardExportPkiPubkey:"+ respApdu.toHexString());
        
        // parse and recover pubkey
        authentikey= parser.parseExportPkiPubkey(respApdu);
        authentikeyHex= parser.toHexString(authentikey);
        System.out.println("Authentikey from cardExportPkiPubkey:"+ authentikeyHex);
        
        return respApdu;
    }  
    
    /****************************************
    *                 CARD MGMT                      *
    ****************************************/
  
    public APDUResponse  cardSetup(byte pin_tries0, byte[] pin0){
    
        // use random values for pin1, ublk0, ublk1
        SecureRandom random = new SecureRandom();
        byte[] ublk0= new byte[8];
        byte[] ublk1= new byte[8];
        byte[] pin1= new byte[8];
        random.nextBytes(ublk0);
        random.nextBytes(ublk1);
        random.nextBytes(pin1);
        
        byte ublk_tries0=(byte)0x01;
        byte ublk_tries1=(byte)0x01;
        byte pin_tries1=(byte)0x01;
        
        return cardSetup(pin_tries0, ublk_tries0, pin0, ublk0, pin_tries1, ublk_tries1, pin1, ublk1);
    }
  
    public APDUResponse  cardSetup(
                    byte pin_tries0, byte ublk_tries0, byte[] pin0, byte[] ublk0,
                    byte pin_tries1, byte ublk_tries1, byte[] pin1, byte[] ublk1){
      
        byte[] pin={0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30}; //default pin
        byte cla= (byte) 0xB0;
        byte ins= INS_SETUP;
        byte p1=0;
        byte p2=0;

        // data=[pin_length(1) | pin |
        //        pin_tries0(1) | ublk_tries0(1) | pin0_length(1) | pin0 | ublk0_length(1) | ublk0 |
        //        pin_tries1(1) | ublk_tries1(1) | pin1_length(1) | pin1 | ublk1_length(1) | ublk1 |
        //        memsize(2) | memsize2(2) | ACL(3) |
        //        option_flags(2) | hmacsha160_key(20) | amount_limit(8)]
        int optionsize=0;
        int option_flags=0; // do not use option (mostly deprecated)
        int offset= 0;
        int datasize= 16+pin.length +pin0.length+pin1.length+ublk0.length+ublk1.length+optionsize;
        byte[] data= new byte[datasize];

        data[offset++]= (byte)pin.length;
        System.arraycopy(pin, 0, data, offset, pin.length);
        offset+= pin.length;
        // pin0 & ublk0
        data[offset++]= pin_tries0;
        data[offset++]= ublk_tries0;
        data[offset++]= (byte)pin0.length;
        System.arraycopy(pin0, 0, data, offset, pin0.length);
        offset+= pin0.length;
        data[offset++]= (byte)ublk0.length;
        System.arraycopy(ublk0, 0, data, offset, ublk0.length);
        offset+= ublk0.length;
        // pin1 & ublk1
        data[offset++]= pin_tries1;
        data[offset++]= ublk_tries1;
        data[offset++]= (byte)pin1.length;
        System.arraycopy(pin1, 0, data, offset, pin1.length);
        offset+= pin1.length;
        data[offset++]= (byte)ublk1.length;
        System.arraycopy(ublk1, 0, data, offset, ublk1.length);
        offset+= ublk1.length;

        // memsize default (deprecated)
        data[offset++]= (byte)00;
        data[offset++]= (byte)32;
        data[offset++]= (byte)00;
        data[offset++]= (byte)32;

        // ACL (deprecated)
        data[offset++]= (byte) 0x01;
        data[offset++]= (byte) 0x01;
        data[offset++]= (byte) 0x01;

        APDUCommand plainApdu = new APDUCommand(cla, ins, p1, p2, data);
        System.out.println("C-APDU cardSetup:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardSetup:"+ respApdu.toHexString());
    
        if (respApdu.isOK()){
            setPin0(pin0);
          
            if (this.cardType.equals("satodime")){ // cache values 
                this.satodimeStatus.updateStatusFromSetup(respApdu);
            }           
        }

        return respApdu;    
    }
  
  
  /****************************************
   *             PIN MGMT                  *
   ****************************************/
    public void setPin0(byte[] pin){
        this.pin0= new byte[pin.length];
        System.arraycopy(pin, 0, this.pin0, 0, pin.length);
    }
   
    public APDUResponse cardVerifyPIN() {
    
        if (pin0 == null){
            // TODO: specific exception
            throw new RuntimeException("PIN required!");
        }
        
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_VERIFY_PIN, 0x00, 0x00, pin0);
        System.out.println("C-APDU cardVerifyPIN:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardVerifyPIN:"+ respApdu.toHexString());
        
        return respApdu;
    }
    
  /****************************************
   *                 BIP32                     *
   ****************************************/
    
    public APDUResponse cardBip32ImportSeed(byte[] masterseed){
        //TODO: check seed (length...)
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_BIP32_IMPORT_SEED, masterseed.length, 0x00, masterseed);

        System.out.println("C-APDU cardBip32ImportSeed:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardBip32ImportSeed:"+ respApdu.toHexString());

        return respApdu;
    }
    
    public APDUResponse cardResetSeed(byte[] pin, byte[] chalresponse){
    
        byte p1= (byte) pin.length;
        byte[] data;
        if (chalresponse==null){
            data= new byte[pin.length];
            System.arraycopy(pin, 0, data, 0, pin.length);
        } else if (chalresponse.length==20){
            data= new byte[pin.length+20];
            int offset=0;
            System.arraycopy(pin, 0, data, offset, pin.length);
            offset+=pin.length;
            System.arraycopy(chalresponse, 0, data, offset, chalresponse.length);
        } else {
            throw new RuntimeException("Wrong challenge-response length (should be 20)");
        }
        
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_BIP32_RESET_SEED, p1, 0x00, data);
        System.out.println("C-APDU cardSignTransactionHash:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardSignTransactionHash:"+ respApdu.toHexString());
        // TODO: check SW code for particular status
        
        return respApdu;
    }
  
    public APDUResponse cardBip32GetExtendedKey(){
        if (defaultBip32path==null){
            defaultBip32path= "m/44'/60'/0'/0/0";
        }
        return cardBip32GetExtendedKey(defaultBip32path);
    }
    
    public APDUResponse cardBip32GetExtendedKey(String stringPath){
    
        KeyPath keyPath= new KeyPath(stringPath);  
        byte[] bytePath= keyPath.getData();
        byte p1= (byte) (bytePath.length/4);
        
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_BIP32_GET_EXTENDED_KEY, p1, 0x40, bytePath);
        System.out.println("C-APDU cardBip32GetExtendedKey:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardBip32GetExtendedKey:"+ respApdu.toHexString());
        // TODO: check SW code for particular status
        
        return respApdu;
    } 
   
  // public APDUResponse cardSignMessage(int keyNbr, byte[] pubkey, String message, byte[] hmac, String altcoin){
  // }
  
   /****************************************
   *             SIGNATURES              *
   ****************************************/
   
    public APDUResponse cardSignTransactionHash(byte keynbr, byte[] txhash, byte[] chalresponse){
    
        byte[] data;
        if (txhash.length !=32){
            throw new RuntimeException("Wrong txhash length (should be 32)");
        }
        if (chalresponse==null){
            data= new byte[32];
            System.arraycopy(txhash, 0, data, 0, txhash.length);
        } else if (chalresponse.length==20){
            data= new byte[32+2+20];
            int offset=0;
            System.arraycopy(txhash, 0, data, offset, txhash.length);
            offset+=32;
            data[offset++]=(byte)0x80; // 2 middle bytes for 2FA flag
            data[offset++]=(byte)0x00;
            System.arraycopy(chalresponse, 0, data, offset, chalresponse.length);
        } else {
            throw new RuntimeException("Wrong challenge-response length (should be 20)");
        }
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_SIGN_TRANSACTION_HASH, keynbr, 0x00, data);
        
        System.out.println("C-APDU cardSignTransactionHash:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardSignTransactionHash:"+ respApdu.toHexString());
        // TODO: check SW code for particular status
        
        return respApdu;
    }
  
  /****************************************
   *               2FA commands            *
   ****************************************/
  
   
  /****************************************
   *                SATODIME              *
   ****************************************/  
   
   
    public APDUResponse satodimeGetStatus(){
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_SATODIME_STATUS, 0x00, 0x00, new byte[0]);
        
        System.out.println("C-APDU satodimeGetStatus:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU satodimeGetStatus:"+ respApdu.toHexString());
        
        satodimeStatus.updateStatus(respApdu);
        //satodimeStatus= new SatodimeStatus(respApdu);
        //satodimeStatus.setUnlockCounter(satodimeStatus.getUnlockCounter());
        
        return respApdu; 
    }
  
    public APDUResponse satodimeGetKeyslotStatus(int keyNbr){
    
        byte keyslot= (byte) (keyNbr%256);
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_SATODIME_KEYSLOT_STATUS, keyslot, 0x00, new byte[0]);
        System.out.println("C-APDU satodimeGetKeyslotStatus:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU satodimeGetKeyslotStatus:"+ respApdu.toHexString());
            
        return respApdu;
    } 
  
    public APDUResponse satodimeSetKeyslotStatusPart0(int keyNbr, int RFU1, int RFU2, int key_asset, byte[] key_slip44, byte[] key_contract, byte[] key_tokenid){
    
        byte keyslot= (byte) (keyNbr%256);
        // check inputs
        if (key_slip44.length!= SIZE_SLIP44){
            throw new RuntimeException("Wrong key_slip44 size (should be 4)");
        }
        if (key_contract.length!= SIZE_CONTRACT){
            throw new RuntimeException("Wrong key_contract size (should be 34)");
        }
        if (key_tokenid.length!= SIZE_TOKENID){
            throw new RuntimeException("Wrong key_tokenid size (should be 34)");
        }
        
        // compute unlock code
        byte[] challenge= new byte[5];
        challenge[0]=CLA;
        challenge[1]=INS_SET_SATODIME_KEYSLOT_STATUS;
        challenge[2]=keyslot;
        challenge[3]=(byte)0x00;
        challenge[4]=(byte)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + 3 + SIZE_SLIP44 + SIZE_CONTRACT + SIZE_TOKENID);
        byte[] unlockCode= satodimeStatus.computeUnlockCode(challenge);
        byte[] data= new byte[unlockCode.length + 3 + SIZE_SLIP44 + SIZE_CONTRACT + SIZE_TOKENID];
        int offset=0;
        System.arraycopy(unlockCode, 0, data, offset, unlockCode.length);
        offset+=unlockCode.length;
        data[offset++]= (byte)RFU1;
        data[offset++]= (byte)RFU2;
        data[offset++]= (byte)key_asset;
        System.arraycopy(key_slip44, 0, data, offset, SIZE_SLIP44);
        offset+=SIZE_SLIP44;
        System.arraycopy(key_contract, 0, data, offset, SIZE_CONTRACT);
        offset+=SIZE_CONTRACT;
        System.arraycopy(key_tokenid, 0, data, offset, SIZE_TOKENID);
        offset+=SIZE_TOKENID;
        
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_SET_SATODIME_KEYSLOT_STATUS, keyslot, 0x00, data);
        
        System.out.println("C-APDU satodimeSetKeyslotStatusPart0:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU satodimeSetKeyslotStatusPart0:"+ respApdu.toHexString());
        if (respApdu.isOK()){
            satodimeStatus.incrementUnlockCounter(); 
        }
        return respApdu;
    }
    
    public APDUResponse satodimeSetKeyslotStatusPart1(int keyNbr, byte[] key_data){
    
        byte keyslot= (byte) (keyNbr%256);
        // check inputs
        if (key_data.length!= SIZE_DATA){
            throw new RuntimeException("Wrong key_data size (should be 66)");
        }
        
        // compute unlock code
        byte[] challenge= new byte[5];
        challenge[0]=CLA;
        challenge[1]=INS_SET_SATODIME_KEYSLOT_STATUS;
        challenge[2]=keyslot;
        challenge[3]=(byte)0x01;
        challenge[4]=(byte)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + SIZE_DATA);
        byte[] unlockCode= satodimeStatus.computeUnlockCode(challenge);
        byte[] data= new byte[unlockCode.length + SIZE_DATA];
        int offset=0;
        System.arraycopy(unlockCode, 0, data, offset, unlockCode.length);
        offset+=unlockCode.length;
        System.arraycopy(key_data, 0, data, offset, SIZE_DATA);
        offset+=SIZE_DATA;
        
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_SET_SATODIME_KEYSLOT_STATUS, keyslot, 0x01, data);
        
        System.out.println("C-APDU satodimeSetKeyslotStatusPart1:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU satodimeSetKeyslotStatusPart1:"+ respApdu.toHexString());
        if (respApdu.isOK()){
            satodimeStatus.incrementUnlockCounter(); 
        }
        return respApdu;
    }
    
    public APDUResponse satodimeGetPubkey(int keyNbr){
    
        byte keyslot= (byte) (keyNbr%256);
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_SATODIME_PUBKEY, keyslot, 0x00, new byte[0]);
        
        System.out.println("C-APDU satodimeGetPubkey:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU satodimeGetPubkey:"+ respApdu.toHexString());
        
        return respApdu;
    }
   
    public APDUResponse satodimeGetPrivkey(int keyNbr){
       
        byte keyslot= (byte) (keyNbr%256);
        
        // compute unlock code
        byte[] challenge= new byte[5];
        challenge[0]=CLA;
        challenge[1]=INS_GET_SATODIME_PRIVKEY;
        challenge[2]=keyslot;
        challenge[3]=(byte)0x00;
        challenge[4]=(byte)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE);
        byte[] unlockCode= satodimeStatus.computeUnlockCode(challenge);
        
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_GET_SATODIME_PRIVKEY, keyslot, 0x00, unlockCode);
        
        System.out.println("C-APDU satodimeGetPrivkey:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU satodimeGetPrivkey:"+ respApdu.toHexString());
        if (respApdu.isOK()){
            satodimeStatus.incrementUnlockCounter(); 
        }
        return respApdu;
    }
   
    public APDUResponse satodimeSealKey(int keyNbr, byte[] entropy_user){
       
       byte keyslot= (byte) (keyNbr%256);
        
        // compute unlock code
        byte[] challenge= new byte[5];
        challenge[0]=CLA;
        challenge[1]=INS_SEAL_SATODIME_KEY;
        challenge[2]=keyslot;
        challenge[3]=(byte)0x00;
        challenge[4]=(byte)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE + SIZE_ENTROPY);
        byte[] unlockCode= satodimeStatus.computeUnlockCode(challenge);
        byte[] data= new byte[unlockCode.length + entropy_user.length];
        System.arraycopy(unlockCode, 0, data, 0, unlockCode.length);
        System.arraycopy(entropy_user, 0, data, unlockCode.length, entropy_user.length);
        
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_SEAL_SATODIME_KEY, keyslot, 0x00, data);
        
        System.out.println("C-APDU satodimeSealKey:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU satodimeSealKey:"+ respApdu.toHexString());
        if (respApdu.isOK()){
            satodimeStatus.incrementUnlockCounter(); 
        }
        return respApdu;
    }
   
    public APDUResponse satodimeUnsealKey(int keyNbr){
       
       byte keyslot= (byte) (keyNbr%256);
        
        // compute unlock code
        byte[] challenge= new byte[5];
        challenge[0]=CLA;
        challenge[1]=INS_UNSEAL_SATODIME_KEY;
        challenge[2]=keyslot;
        challenge[3]=(byte)0x00;
        challenge[4]=(byte)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE);
        byte[] unlockCode= satodimeStatus.computeUnlockCode(challenge);
        
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_UNSEAL_SATODIME_KEY, keyslot, 0x00, unlockCode);
        
        System.out.println("C-APDU satodimeUnsealKey:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU satodimeUnsealKey:"+ respApdu.toHexString());
        if (respApdu.isOK()){
            satodimeStatus.incrementUnlockCounter(); 
        }
        return respApdu;
    }
   
    public APDUResponse satodimeResetKey(int keyNbr){
       
        byte keyslot= (byte) (keyNbr%256);

        // compute unlock code
        byte[] challenge= new byte[5];
        challenge[0]=CLA;
        challenge[1]=INS_RESET_SATODIME_KEY;
        challenge[2]=keyslot;
        challenge[3]=(byte)0x00;
        challenge[4]=(byte)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE);
        byte[] unlockCode= satodimeStatus.computeUnlockCode(challenge);

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_RESET_SATODIME_KEY, keyslot, 0x00, unlockCode);

        System.out.println("C-APDU satodimeResetKey:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU satodimeResetKey:"+ respApdu.toHexString());
        if (respApdu.isOK()){
            satodimeStatus.incrementUnlockCounter(); 
        }
        return respApdu;
    }
   
    public APDUResponse satodimeInitiateOwnershipTransfer(){
       
        // compute unlock code
        byte[] challenge= new byte[5];
        challenge[0]=CLA;
        challenge[1]=INS_INITIATE_SATODIME_TRANSFER;
        challenge[2]=(byte)0x00;
        challenge[3]=(byte)0x00;
        challenge[4]=(byte)(SIZE_UNLOCK_COUNTER + SIZE_UNLOCK_CODE);
        byte[] unlockCode= satodimeStatus.computeUnlockCode(challenge);

        APDUCommand plainApdu = new APDUCommand(0xB0, INS_INITIATE_SATODIME_TRANSFER, 0x00, 0x00, unlockCode);
        
        System.out.println("C-APDU satodimeInitiateOwnershipTransfer:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU satodimeInitiateOwnershipTransfer:"+ respApdu.toHexString());
        if (respApdu.isOK()){
            satodimeStatus.incrementUnlockCounter(); 
        }
        return respApdu;
    }
 
    /****************************************
    *            PKI commands              *
    ****************************************/  
    
    public APDUResponse cardExportPersoPubkey(){
        
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_EXPORT_PKI_PUBKEY, 0x00, 0x00, new byte[0]);
        System.out.println("C-APDU cardExportPersoPubkey:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardExportPersoPubkey:"+ respApdu.toHexString());
        
        return respApdu;
    }
    
    public String cardExportPersoCertificate(){
        
        // init
        byte p1= 0x00;
        byte p2= 0x01; // init
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_EXPORT_PKI_CERTIFICATE, p1, p2, new byte[0]);
        System.out.println("C-APDU cardExportPersoCertificate - init:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardExportPersoCertificate - init:"+ respApdu.toHexString());
        
        int sw= respApdu.getSw();
        byte[] response=null;
        int certificate_size=0;
        if (sw== 0x9000){
            response= respApdu.getData();
            certificate_size= (response[0] & 0xFF)*256 + (response[1] & 0xFF);
        } else if (sw== 0x6D00){
            System.out.println("Error during personalization certificate export: command unsupported(0x6D00)");
            return "Error during personalization certificate export: command unsupported(0x6D00)";
        } else if (sw==0x0000){
            System.out.println("Error during personalization certificate export: no card present(0x0000)");
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
            System.out.println("C-APDU cardExportPersoCertificate - update:"+ plainApdu.toHexString());
            respApdu = this.cardTransmit(plainApdu);
            System.out.println("R-APDU cardExportPersoCertificate - update:"+ respApdu.toHexString());
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
        System.out.println("C-APDU cardExportPersoCertificate - final:"+ plainApdu.toHexString());
        respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardExportPersoCertificate - final:"+ respApdu.toHexString());
        // update certificate
        response= respApdu.getData();
        System.arraycopy(response, 0, certificate, cert_offset, remaining_size);
        cert_offset+=remaining_size;
        
        // TODO parse and return raw certificate
        String cert_pem= parser.convertBytesToStringPem(certificate);
        
        return cert_pem;
    }
    
    public APDUResponse cardChallengeResponsePerso(byte[] challenge_from_host){
        
        APDUCommand plainApdu = new APDUCommand(0xB0, INS_CHALLENGE_RESPONSE_PKI, 0x00, 0x00, challenge_from_host);
        System.out.println("C-APDU cardChallengeResponsePerso:"+ plainApdu.toHexString());
        APDUResponse respApdu = this.cardTransmit(plainApdu);
        System.out.println("R-APDU cardChallengeResponsePerso:"+ respApdu.toHexString());
        
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
            System.out.println("Cert PEM: "+ cert_pem);
        } catch (Exception e){
            System.out.println("Exception in cardVerifyAuthenticity:"+ e);
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
            System.out.println("isCa: " + isCa); 
            //TODO: load subca cert depending on card type
            InputStream isSubca = this.getClass().getClassLoader().getResourceAsStream("cert/subca-satodime.cert"); 
            System.out.println("isSubca: " + isSubca); 
            InputStream isDevice = new ByteArrayInputStream(cert_pem.getBytes(StandardCharsets.UTF_8));
            System.out.println("isDevice: " + isDevice); 
            // gen certs
            CertificateFactory certificateFactory= CertificateFactory.getInstance("X.509", "BC"); // without BC provider, validation fails...
            Certificate certCa = certificateFactory.generateCertificate(isCa);
            txt_ca= certCa.toString();
            System.out.println("certCa: " + txt_ca); 
            Certificate certSubca = certificateFactory.generateCertificate(isSubca);
            txt_subca= certSubca.toString();
            System.out.println("certSubca: " + txt_subca); 
            Certificate certDevice = certificateFactory.generateCertificate(isDevice);
            txt_device= certDevice.toString();
            System.out.println("certDevice: " + txt_device); 
            
            pubkeyDevice= certDevice.getPublicKey();
            System.out.println("certDevice pubkey: " + pubkeyDevice.toString()); 
            
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
            System.out.println("Certificate chain validated!");
            
        }catch (Exception e){
            System.out.println("Exception in cardVerifyAuthenticity:"+ e);
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
            System.out.println("Exception in cardVerifyAuthenticity:"+ e);
            e.printStackTrace();
            txt_error= "Failed to verify challenge-response! \r\n\r\n" + e.toString();
            String[] out = new String [] {FAIL, txt_ca, txt_subca, txt_device, txt_error};
            return out;
        }       
        
        String[] out =  new String [] {OK, txt_ca, txt_subca, txt_device, txt_error};
        return out;
    }
}
