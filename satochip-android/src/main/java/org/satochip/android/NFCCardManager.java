package org.satochip.android;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.util.Log;
import org.satochip.io.CardListener;

import java.io.IOException;

/**
 * Manages connection of NFC-based cards and notifies a {@link CardListener}.
 *
 * <p>Register it as the {@link NfcAdapter.ReaderCallback} (or forward tags to
 * {@link #onTagDiscovered(Tag)}). For each tag, {@code onTagDiscovered} connects to the card, calls
 * {@link CardListener#onConnected} on the calling thread (the NFC reader thread, not the UI thread),
 * then closes the connection and calls {@link CardListener#onDisconnected}. The channel passed to
 * {@code onConnected} is therefore only valid during that call: do the whole card session there.</p>
 *
 * <p>There is no polling thread. The class still extends {@link Thread} so that existing code
 * calling {@code start()} keeps compiling, but starting it is no longer needed and does nothing.</p>
 */
public class NFCCardManager extends Thread implements NfcAdapter.ReaderCallback {
  private static final String TAG = "NFCCardManager";
  private static final int TIMEOUT_MS = 120000;

  private volatile IsoDep isoDep;
  private volatile CardListener cardListener;

  /**
   * Constructs an NFC Card Manager.
   */
  public NFCCardManager() {
  }

  /**
   * Constructs an NFC Card Manager.
   *
   * @param loopSleepMS ignored, there is no polling loop anymore
   * @deprecated use {@link #NFCCardManager()}
   */
  @Deprecated
  public NFCCardManager(int loopSleepMS) {
    this();
  }

  /**
   * True while a card session is in progress and the tag is still in range.
   *
   * @return true if connected, false otherwise
   */
  public boolean isConnected() {
    IsoDep current = isoDep;
    try {
      return current != null && current.isConnected();
    } catch (RuntimeException e) {
      // IsoDep.isConnected() throws SecurityException ("Tag ... is out of date") once the tag is gone
      return false;
    }
  }

  /**
   * Connects to the tag, runs the listener's card session, then disconnects.
   *
   * <p>Called by Android on the NFC reader thread; the call blocks for the whole card session.
   * Tags are handled one at a time.</p>
   *
   * @param tag the discovered tag
   */
  @Override
  public synchronized void onTagDiscovered(Tag tag) {
    IsoDep tagIsoDep = IsoDep.get(tag);
    if (tagIsoDep == null) {
      Log.w(TAG, "tag does not support IsoDep, ignored");
      return;
    }
    try {
      tagIsoDep.connect();
      tagIsoDep.setTimeout(TIMEOUT_MS);
    } catch (IOException | RuntimeException e) {
      Log.w(TAG, "error connecting to tag: " + e);
      return;
    }

    isoDep = tagIsoDep;
    Log.d(TAG, "tag connected");
    try {
      CardListener listener = cardListener;
      if (listener != null) {
        listener.onConnected(new NFCCardChannel(tagIsoDep));
      }
    } catch (RuntimeException e) {
      Log.w(TAG, "card listener failed: " + e);
    } finally {
      isoDep = null;
      try {
        tagIsoDep.close();
      } catch (IOException | RuntimeException e) {
        // the tag is already gone
      }
      Log.d(TAG, "tag disconnected");
      CardListener listener = cardListener;
      if (listener != null) {
        listener.onDisconnected();
      }
    }
  }

  /**
   * Does nothing: card sessions run from {@link #onTagDiscovered(Tag)}.
   *
   * @deprecated there is no polling loop anymore, starting this thread is not needed
   */
  @Deprecated
  @Override
  public void run() {
  }

  /**
   * Sets the card listener.
   *
   * @param listener the new listener
   */
  public void setCardListener(CardListener listener) {
    cardListener = listener;
  }
}
