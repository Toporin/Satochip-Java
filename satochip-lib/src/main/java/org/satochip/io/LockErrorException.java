package org.satochip.io;

/**
 * Exception thrown when the card answers with SW_LOCK_ERROR (0x9C30).
 *
 * <p>SeedKeeper locks a multi-step operation (e.g. a secret import or export sent in several
 * commands) until it completes. If the operation is interrupted, for instance by removing the card,
 * the card rejects the next command once with this status word and releases the lock, so the
 * command can simply be sent again.</p>
 *
 * <p>Being an {@link APDUException}, it is still caught by existing handlers, and {@link #sw} is
 * still 0x9C30.</p>
 */
public class LockErrorException extends APDUException {

  /**
   * Creates the exception with the given message.
   *
   * @param message a descriptive message of the error
   */
  public LockErrorException(String message) {
    super(APDUResponse.SW_LOCK_ERROR, message);
  }
}
