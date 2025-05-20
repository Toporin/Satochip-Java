# satochip-android Documentation

This document outlines the public methods available in the `satochip-android` library, which facilitates NFC communication with Satochip/Satodime/SeedKeeper cards on Android.

## `org.satochip.android.NFCCardManager`

Manages the NFC connection lifecycle for ISO-DEP compatible smart cards. It runs as a background thread to monitor tag connection/disconnection events and notifies a listener.

**Important:** This class extends `Thread` and implements `NfcAdapter.ReaderCallback`. You must start it using the `start()` method and register it with the `NfcAdapter`'s `enableReaderMode()` method in your Android Activity.

### Constructors

*   `NFCCardManager()`: Constructs an instance with a default polling interval (`DEFAULT_LOOP_SLEEP_MS = 50`).
*   `NFCCardManager(int loopSleepMS)`: Constructs an instance with a specified polling interval in milliseconds.

### Connection Management

*   `boolean isConnected()`: Returns `true` if a tag is currently connected via `IsoDep`, `false` otherwise.
*   `void onTagDiscovered(Tag tag)`: **(Callback)** This method is called by the Android NFC system when a compatible tag is discovered. It establishes the `IsoDep` connection and sets a timeout.
*   `void run()`: **(Internal)** The main run loop of the thread. Monitors connection state changes and triggers `onCardConnected`/`onCardDisconnected`. Do not call directly; use `start()`.

### Listener Management

*   `void setCardListener(CardListener listener)`: Sets the listener that will receive connection and disconnection events. The listener (typically your Activity or a dedicated handler) will receive an `NFCCardChannel` upon connection.

## `org.satochip.android.NFCCardChannel`

An implementation of the `satochip-lib`'s `CardChannel` interface using Android's `IsoDep` for NFC communication.

### Constructor

*   `NFCCardChannel(IsoDep isoDep)`: Creates a channel instance linked to an established `IsoDep` connection.

### Communication Methods

*   `APDUResponse send(APDUCommand cmd)`: Sends an `APDUCommand` to the connected card via `isoDep.transceive()` and returns the `APDUResponse`. Throws `IOException` if communication fails.
*   `boolean isConnected()`: Returns `true` if the underlying `IsoDep` object is connected, `false` otherwise. 