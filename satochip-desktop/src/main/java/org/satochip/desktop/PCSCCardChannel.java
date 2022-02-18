package org.satochip.desktop;

import org.satochip.globalplatform.Crypto;
import org.satochip.io.APDUCommand;
import org.satochip.io.APDUResponse;
import org.satochip.io.CardChannel;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.IOException;

/**
 * Implementation of a CardChannel using the Java Smartcard I/O API,
 */
public class PCSCCardChannel implements CardChannel {
  static {
    Crypto.addBouncyCastleProvider();
  }

  private javax.smartcardio.CardChannel cardChannel;

  /**
   * Constructor. Wraps a Java Smartcard I/O CardChannel.
   * @param cardChannel the card channel to wrap.
   */
  public PCSCCardChannel(javax.smartcardio.CardChannel cardChannel) {
    this.cardChannel = cardChannel;
  }

  @Override
  public APDUResponse send(APDUCommand cmd) throws IOException {
    CommandAPDU capdu = new CommandAPDU(cmd.getCla(), cmd.getIns(), cmd.getP1(), cmd.getP2(), cmd.getData(), cmd.getNeedsLE() ? 0x100 : 0x00);

    ResponseAPDU rapdu;

    try {
      rapdu = cardChannel.transmit(capdu);
    } catch (CardException e) {
      throw new IOException(e);
    }

    return new APDUResponse(rapdu.getBytes());
  }

  @Override
  public boolean isConnected() {
    return true;
  }
}
