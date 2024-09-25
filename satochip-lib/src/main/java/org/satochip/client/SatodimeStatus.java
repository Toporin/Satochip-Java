package org.satochip.client;

import static org.satochip.client.Constants.*;
import org.satochip.io.APDUResponse;

import java.util.Arrays;
import java.nio.ByteBuffer;
import java.util.logging.Logger;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 * Parses the result of a SATODIME_GET_STATUS command retrieving application status.
 */
public class SatodimeStatus {
    
    private static final Logger logger = Logger.getLogger("org.satochip.client");
    
    private boolean setup_done= false;
    private boolean isOwner= false;
    private int max_num_keys=0;
    private byte[] satodime_keys_state= null;
    private byte[] unlock_counter= null;
    private byte[] unlock_secret= null;
    
    public SatodimeStatus() {
        unlock_counter= new byte[SIZE_UNLOCK_COUNTER];
        unlock_secret= new byte[SIZE_UNLOCK_SECRET];
    }
    
    public void updateStatus(APDUResponse rapdu) {
    
        int sw= rapdu.getSw();
        if (sw==0x9000){
            //data: [unlock_counter | nb_keys_slots(1b) | key_status(nb_key_slots bytes) ]
            byte[] data= rapdu.getData();
            setup_done= true;

            int offset=0;
            int dataRemain= data.length;
            // unlock_counter
            if (dataRemain<SIZE_UNLOCK_COUNTER){
                throw new RuntimeException("Exception in SatodimeStatus: wrong data length");
            }
            System.arraycopy(data, offset, unlock_counter, 0, SIZE_UNLOCK_COUNTER);
            offset+=SIZE_UNLOCK_COUNTER;
            dataRemain-=SIZE_UNLOCK_COUNTER;
            // max_num_keys
            if (dataRemain<1){
                throw new RuntimeException("Exception in SatodimeStatus: wrong data length");
            }
            max_num_keys= data[offset++];
            dataRemain--;
            // satodime_keys_state
            if (dataRemain<max_num_keys){
                throw new RuntimeException("Exception in SatodimeStatus: wrong data length");
            }
            satodime_keys_state = new byte[max_num_keys];
            System.arraycopy(data, offset, satodime_keys_state, 0, max_num_keys);
        }
        else if (sw==0x9c04){
            setup_done= false;
        }
        else{
            //throws IllegalArgumentException("Wrong getStatus data!"); // should not happen
        }
    }
    
    public void updateStatusFromSetup(APDUResponse rapduSetup){
        int sw= rapduSetup.getSw();
        if (sw==0x9000){
            setup_done= true;
            byte[] data= rapduSetup.getData();
            int offset=0;
            System.arraycopy(data, offset, unlock_counter, 0, SIZE_UNLOCK_COUNTER);
            offset+= SIZE_UNLOCK_COUNTER;
            System.arraycopy(data, offset, unlock_secret, 0, SIZE_UNLOCK_SECRET);
            isOwner= true;
        } else {
             // TODO: throw?
        }
    }
    
  /**
   * Constructor from TLV data
   * @param tlvData the TLV data
   * @throws IllegalArgumentException if the TLV does not follow the expected format
   */
 /*  public SatodimeStatus(APDUResponse rapdu) {
    
    int sw= rapdu.getSw();
    
    if (sw==0x9000){
      
      //data: [unlock_counter | nb_keys_slots(1b) | key_status(nb_key_slots bytes) ]
      byte[] data= rapdu.getData();
      setup_done= true;
      
      int offset=0;
      int dataRemain= data.length;
      // unlock_counter
      if (dataRemain<SIZE_UNLOCK_COUNTER){
        throw new RuntimeException("Exception in SatodimeStatus: wrong data length");
      }
      unlock_counter= new byte[SIZE_UNLOCK_COUNTER];
      System.arraycopy(data, offset, unlock_counter, 0, SIZE_UNLOCK_COUNTER);
      offset+=SIZE_UNLOCK_COUNTER;
      dataRemain-=SIZE_UNLOCK_COUNTER;
      // max_num_keys
      if (dataRemain<1){
        throw new RuntimeException("Exception in SatodimeStatus: wrong data length");
      }
      max_num_keys= data[offset++];
      dataRemain--;
      // satodime_keys_state
      if (dataRemain<max_num_keys){
        throw new RuntimeException("Exception in SatodimeStatus: wrong data length");
      }
      satodime_keys_state = new byte[max_num_keys];
      System.arraycopy(data, offset, satodime_keys_state, 0, max_num_keys);
      
    }
    else if (sw==0x9c04){
      setup_done= false;
    }
    else{
      //throws IllegalArgumentException("Wrong getStatus data!"); // should not happen
    }
  } */
  
  // getters
  public boolean isSetupDone() {
    return setup_done;
  }
  
  public boolean isOwner(){
      return isOwner;
  }
  
  public int getMaxNumKeys(){
    return max_num_keys;
  }
  
  public byte[] getKeysState(){
    return satodime_keys_state;
  }
  
  // printer
  public String toString(){
    String status_info=   "setup_done: " + setup_done + "\n" +
                                  "max_num_keys: " + max_num_keys + "\n" +
                                  "satodime_keys_state: " + Arrays.toString(satodime_keys_state);
    return status_info;
  }
  
    /**********************************************
    *           UNLOCKING LOGIC
    **********************************************/
  
    public byte[] getUnlockCounter(){
        return unlock_counter;
    }
  
    public void setUnlockSecret(byte[] unlock_secret){
        System.arraycopy(unlock_secret, 0, this.unlock_secret, 0, SIZE_UNLOCK_SECRET);
        isOwner= true;
    }
    
    // todo: remove?
    public byte[] getUnlockSecret(){
        return this.unlock_secret;
    }
     // todo: remove?
    public void setUnlockCounter(byte[] unlock_counter){
        logger.info("SATOCHIPLIB: setUnlockCounter: "+ Hex.toHexString(unlock_counter));
        if (unlock_counter!=null){
            System.arraycopy(unlock_counter, 0, this.unlock_counter, 0, SIZE_UNLOCK_COUNTER);
        }
    }
  
    public void incrementUnlockCounter(){
        logger.info("SATOCHIPLIB: incrementUnlockCounter: "+ Hex.toHexString(unlock_counter));
        // convert byte array to int
        ByteBuffer bb = ByteBuffer.wrap(this.unlock_counter); // big-endian by default
        int counterInt= bb.getInt(); 
        counterInt++; 
        // convert back to byte array
        ByteBuffer bb2 = ByteBuffer.allocate(4);
        bb2.putInt(counterInt); // big endian
        this.unlock_counter= bb2.array();        
    }
    
    public byte[] computeUnlockCode(byte[] challenge){
        logger.info("SATOCHIPLIB: computeUnlockCode counter: "+ Hex.toHexString(unlock_counter));
        HMac hMac = new HMac(new SHA1Digest());
        hMac.init(new KeyParameter(unlock_secret));
        hMac.update(challenge, 0, challenge.length);
        hMac.update(unlock_counter, 0, SIZE_UNLOCK_COUNTER);
        byte[] code = new byte[20];
        hMac.doFinal(code, 0);
        
        byte[] response= new byte[SIZE_UNLOCK_COUNTER+20];
        System.arraycopy(unlock_counter, 0, response, 0, SIZE_UNLOCK_COUNTER);
        System.arraycopy(code, 0, response, SIZE_UNLOCK_COUNTER, code.length);
        
        return response;
    }
  
}
