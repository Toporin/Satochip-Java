package org.satochip.io;

/**
 * Exception thrown when checking PIN/PUK
 */
public class BlockedPINException extends APDUException {
  
  /**
   * Construct an exception with the given number of retry attempts.
   */
  public BlockedPINException() {
    super("PIN blocked");
  }
}
