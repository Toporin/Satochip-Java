package org.satochip.android;

import android.nfc.tech.IsoDep;
import org.satochip.io.APDUCommand;
import org.satochip.io.APDUResponse;
import org.satochip.io.CardChannel;

import java.io.IOException;

/**
 * Implementation of the CardChannel interface using the Android NFC API.
 */
public class NFCCardChannel implements CardChannel {
  private IsoDep isoDep;

  public NFCCardChannel(IsoDep isoDep) {
    this.isoDep = isoDep;
  }

  @Override
  public APDUResponse send(APDUCommand cmd) throws IOException {
    // Not logged here: SatochipCommandSet logs each command before secure channel encryption,
    // whereas this channel would only see the encrypted envelope.
    byte[] apdu = cmd.serialize();
    byte[] resp = this.isoDep.transceive(apdu);
    return new APDUResponse(resp);
  }

  @Override
  public boolean isConnected() {
    return this.isoDep.isConnected();
  }
}
