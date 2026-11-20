package org.satochip.client;

import org.satochip.io.APDUResponse;

/**
 * Parses the result of a GET STATUS command retrieving application status.
 */
public class ApplicationStatus {
  
    private boolean setup_done= false;
    private boolean is_seeded= false;
    private boolean needs_secure_channel= false;
    private boolean needs_2FA= false;
    private boolean supports_taproot = false;
    private boolean supports_taproot_multisig = false;

    private byte protocol_major_version= (byte)0;
    private byte protocol_minor_version= (byte)0;
    private byte applet_major_version= (byte)0;
    private byte applet_minor_version= (byte)0;

    private byte PIN0_remaining_tries= (byte)0;
    private byte PUK0_remaining_tries= (byte)0;
    private byte PIN1_remaining_tries= (byte)0;
    private byte PUK1_remaining_tries= (byte)0;

    private int protocol_version= 0; //(d["protocol_major_version"]<<8)+d["protocol_minor_version"] 

    // todo: remove
    // private byte pinRetryCount;
    // private byte pukRetryCount;
    // private boolean hasMasterKey;


    /**
    * Constructor from TLV data
    * @param tlvData the TLV data
    * @throws IllegalArgumentException if the TLV does not follow the expected format
    */
    public ApplicationStatus(APDUResponse rapdu) {
    
        int sw= rapdu.getSw();
        
        if (sw==0x9000 && rapdu.getData().length >= 4){
          
            byte[] data= rapdu.getData();
            protocol_major_version= data[0];
            protocol_minor_version= data[1];
            applet_major_version= data[2];
            applet_minor_version= data[3];
            // Mask the bytes: a minor version of 0x80 or above would otherwise sign-extend
            // to a negative int and make version comparisons wrong.
            protocol_version= ((protocol_major_version & 0xff)<<8) + (protocol_minor_version & 0xff);
      
            if (data.length >=8){
                PIN0_remaining_tries= data[4];
                PUK0_remaining_tries= data[5];
                PIN1_remaining_tries= data[6];
                PUK1_remaining_tries= data[7];
                needs_2FA= false; //default value
            }
            if (data.length >=9){
                needs_2FA= (data[8]==0X00)? false : true;
            }
            if (data.length >=10){
                is_seeded= (data[9]==0X00)? false : true;
            } 
            if (data.length >=11){
                setup_done= (data[10]==0X00)? false : true;
            } else {
                setup_done= true;
            }
            if (data.length >=12){
                needs_secure_channel= (data[11]==0X00)? false : true;   
            } else {
                needs_secure_channel= false;
            }

            long version = ((data[0] & 0xffL) << 24) | ((data[1] & 0xffL) << 16)
                    | ((data[2] & 0xffL) << 8) | (data[3] & 0xffL);
            // Policies: Schnorr at 13 (since 0.14-0.5), MuSig2 at 16; 0 = enabled.
            boolean schnorr_enabled = data.length >= 16 && data[13] == 0;
            // Require protocol 0.16: earlier applets compute a non-BIP341 Taproot tweak
            // (tagged hash over x(P) XOR h instead of x(P) || h).
            supports_taproot = version >= 0x00100000L && schnorr_enabled;
            // Require 0.15-0.1's protection against encrypted nonce replay.
            supports_taproot_multisig = supports_taproot && version >= 0x000f0001L
                    && data.length >= 17 && data[16] == 0;
        } else if (sw==0x9c04){
            setup_done= false;
            is_seeded= false;
            needs_secure_channel= false;
        } else{
            //throws IllegalArgumentException("Wrong getStatus data!"); // should not happen
        }
    }
  
    // getters
    public boolean isSeeded() {
        return is_seeded;
    }
    public boolean isSetupDone() {
        return setup_done;
    }
    public boolean needsSecureChannel() {
        return needs_secure_channel;
    }
    public boolean needs2FA() {
        return needs_2FA;
    }

    public boolean supportsTaproot() {
        return supports_taproot;
    }

    public boolean supportsTaprootMultisig() {
        return supports_taproot_multisig;
    }

    // TODO: other gettters
    public byte getPin0RemainingCounter(){
        return PIN0_remaining_tries;
    }
    public byte getPuk0RemainingCounter(){
        return PUK0_remaining_tries;
    }

    public String toString(){
        String status_info=   "setup_done: " + setup_done + "\n"+
                                  "is_seeded: " + is_seeded + "\n"+
                                  "needs_2FA: " + needs_2FA + "\n"+
                                  "needs_secure_channel: " + needs_secure_channel + "\n"+
                                  "protocol_major_version: " + protocol_major_version + "\n"+
                                  "protocol_minor_version: " + protocol_minor_version + "\n"+
                                  "applet_major_version: " + applet_major_version + "\n"+
                                  "applet_minor_version: " + applet_minor_version;
        return status_info;
    }
    public int getCardVersionInt() {
        return ((int) protocol_major_version * (1 << 24)) +
                ((int) protocol_minor_version * (1 << 16)) +
                ((int) applet_major_version * (1 << 8)) +
                ((int) applet_minor_version);
    }

    public String getCardVersionString() {
        String version_string =
            protocol_major_version + "." + 
            protocol_minor_version + "-" +
            applet_major_version + "." + 
            applet_minor_version;
        return version_string;
    }

    /**
     * Returns the applet protocol version as {@code (major << 8) | minor}, so protocol 0.16 is
     * reported as 0x0010. Use it to gate behaviour that changed with a protocol revision.
     *
     * @return the protocol version, or 0 if the status could not be parsed
     */
    public int getProtocolVersion() {
        return protocol_version;
    }
}
