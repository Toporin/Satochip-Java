package org.satochip.client;

import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

public class Identifiers {
	
  public static final byte[] SATOCHIP_AID = Hex.decode("5361746f43686970"); //SatoChip
  public static final byte[] SEEDKEEPER_AID = Hex.decode("536565644b6565706572"); //SeedKeeper
  public static final byte[] SATODIME_AID = Hex.decode("5361746f44696d65"); //SatoDime 
  // public static final byte[] PACKAGE_AID = Hex.decode("A0000008040001");
  // public static final byte[] KEYCARD_AID = Hex.decode("A000000804000101");
  // public static final int KEYCARD_DEFAULT_INSTANCE_IDX = 1;
  // public static final byte[] NDEF_AID = Hex.decode("A000000804000102");
  // public static final byte[] NDEF_INSTANCE_AID = Hex.decode("D2760000850101");
  // public static final byte[] CASH_AID = Hex.decode("A000000804000103");
  // public static final byte[] CASH_INSTANCE_AID = Hex.decode("A00000080400010301");

  /**
   * Gets the instance AID of the default instance of the Keycard applet.
   *
   * @return the instance AID of the Keycard applet
   */
  public static byte[] getSatochipInstanceAID() {
    return SATOCHIP_AID;
  }
  
}
