package org.satochip.io;

/**
 * Exception thrown when checking PIN/PUK
 */
public class WrongPINLegacyException extends APDUException {
  
  /**
   * Construct an exception with the given number of retry attempts.
   */
  public WrongPINLegacyException() {
    super("Wrong PIN Legacy");
  }
}
