package org.satochip.client;

import static org.satochip.client.Constants.*;
import org.satochip.io.APDUResponse;

import java.util.Arrays;

/**
 * Parses the result of a SATODIME_GET_STATUS command retrieving application status.
 */
public class SatodimeKeyslotStatus {
  
  private boolean setup_done= false;
  private byte keyStatus;
  private byte keyType;
  private byte keyAsset;
  private byte[] keySlip44= null;
  private byte[] keyContract= null;
  private byte[] keyTokenId= null;
  private byte[] keyData= null;
  private byte[] tmpBuffer= null;
  /**
   * Constructor from TLV data
   * @param tlvData the TLV data
   * @throws IllegalArgumentException if the TLV does not follow the expected format
   */
  public SatodimeKeyslotStatus(APDUResponse rapdu) {
    
    int sw= rapdu.getSw();
    
    if (sw==0x9000){
      
      //data: [ key_status(1b) | key_type(1b) | key_asset(1b) | key_slip44(4b) | key_contract(34b) | key_tokenid(34b) | key_data(66b) ]
      byte[] data= rapdu.getData();
      setup_done= true;
      tmpBuffer= new byte[SIZE_DATA];
      
      int offset=0;
      int dataRemain= data.length;
      // keyStatus, keyType, keyAsset
      if (dataRemain<3){
        throw new RuntimeException("Exception in SatodimeKeyslotStatus: wrong data length 1");
      }
      keyStatus= data[offset++];
      keyType= data[offset++];
      keyAsset= data[offset++];
      dataRemain-=3;
      // slip44
      if (dataRemain<SIZE_SLIP44){
        throw new RuntimeException("Exception in SatodimeKeyslotStatus: wrong data length 2");
      }
      keySlip44= new byte[SIZE_SLIP44];
      System.arraycopy(data, offset, keySlip44, 0, SIZE_SLIP44);
      offset+= SIZE_SLIP44;
      dataRemain-=SIZE_SLIP44;
      // parse contract TLV bytes
      if (dataRemain<SIZE_CONTRACT){
        throw new RuntimeException("Exception in SatodimeKeyslotStatus: wrong data length 3");
      }
      System.arraycopy(data, offset, tmpBuffer, 0, SIZE_CONTRACT);
      int contractSize= tmpBuffer[1] & 0xff; // tmpBuffer[0] is RFU (contract type?)
      if (contractSize>(SIZE_CONTRACT-2)){
        throw new RuntimeException("Exception in SatodimeKeyslotStatus: wrong contract size: " + contractSize);
      }
      keyContract= new byte[contractSize];
      System.arraycopy(tmpBuffer, 2, keyContract, 0, contractSize);
      offset+= SIZE_CONTRACT;
      dataRemain-=SIZE_CONTRACT;
      // parse tokenid TLV bytes
      if (dataRemain<SIZE_TOKENID){
        throw new RuntimeException("Exception in SatodimeKeyslotStatus: wrong data length 4");
      }
      System.arraycopy(data, offset, tmpBuffer, 0, SIZE_TOKENID);
      int tokenidSize= tmpBuffer[1] & 0xff; // tmpBuffer[0] is RFU (tokenid type?)
      if (tokenidSize>(SIZE_TOKENID-2)){
        throw new RuntimeException("Exception in SatodimeKeyslotStatus: wrong tokenId size: " + tokenidSize);
      }
      keyTokenId= new byte[tokenidSize];
      System.arraycopy(tmpBuffer, 2, keyTokenId, 0, tokenidSize);
      offset+= SIZE_TOKENID;
      dataRemain-=SIZE_TOKENID;
      // parse metadata TLV bytes
      if (dataRemain<SIZE_DATA){
        throw new RuntimeException("Exception in SatodimeKeyslotStatus: wrong data length 5");
      }
      System.arraycopy(data, offset, tmpBuffer, 0, SIZE_DATA);
      int dataSize= tmpBuffer[1] & 0xff; // tmpBuffer[0] is RFU (data type?)
      if (dataSize>(SIZE_DATA-2)){
        throw new RuntimeException("Exception in SatodimeKeyslotStatus: wrong data size: " + dataSize);
      }
      keyData= new byte[dataSize];
      System.arraycopy(tmpBuffer, 2, keyData, 0, dataSize);
      offset+= SIZE_DATA;
      dataRemain-=SIZE_DATA;
    }
    else if (sw==0x9c04){
      setup_done= false;
    }
    else{
      //throws IllegalArgumentException("Wrong getStatus data!"); // should not happen
    }
  }
  
  // getters
  public boolean isSetupDone() {
    return setup_done;
  }
  
  public byte getKeyStatus(){
    return keyStatus;
  }
  
  public byte getKeyType(){
    return keyType;
  }
  
  public byte getKeyAsset(){
    return keyAsset;
  }
  
  public byte[] getKeySlip44(){
    return keySlip44;
  }
  
  public byte[] getKeyContract(){
    return keyContract;
  }
  
  public byte[] getKeyTokenId(){
    return keyTokenId;
  }
  
  public byte[] getKeyData(){
    return keyData;
  }
  
  // to string
  public String toString(){
    String keyslotInfo= "setup_done: " + setup_done + "\n" +
                                  "keyStatus: " + keyStatus + "\n" +
                                  "keyType: " + keyType + "\n" +
                                  "keyAsset: " + keyAsset + "\n" +
                                  "keySlip44: " + Arrays.toString(keySlip44) + "\n" +
                                  "keyContract: " + Arrays.toString(keyContract) + "\n" +
                                  "keyTokenId: " + Arrays.toString(keyTokenId) + "\n" +
                                  "keyData: " + Arrays.toString(keyData) + "\n";
    return keyslotInfo;
  }
  
  
  
}
