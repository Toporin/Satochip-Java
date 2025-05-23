# Satochip-Java Library Documentation

## Overview

The Satochip-Java library provides a comprehensive SDK for integrating smartcard devices with Android and Desktop applications.
It supports three types of smartcards:

- **Satochip**: A hardware wallet with BIP32 support for importing BIP39 seeds and signing transactions
- **Satodime**: A bearer bitcoin card that securely generates and stores private keys and allows to redeem the funds by unsealing the keys.
- **Seedkeeper**: A secure backup solution for seeds, descriptors, passwords and other sensitive data.

Satochip and Seedkeeper require a user PIN to access most card functionalities. Satodime is a bearer card: the card assets belong the person who owns it.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Core Architecture](#core-architecture)
3. [Basic Usage Flow](#basic-usage-flow)
4. [Command Reference](#command-reference)
5. [Best practices](#best-practices)
6. [Additional Resources](#additional-resources)

## Getting Started (Android)

### Installation

Add the library to your Android project:

```gradle
dependencies {
    implementation files('libs/satochip-lib-0.2.3.jar')
    implementation files('libs/satochip-android-0.0.2.jar')
}
```

### Permissions

Add NFC permissions to your `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.NFC" />
```

## Core Architecture

### Libraries

- **`satochip-lib`**: main library that handles the Satochip/Satodime/Seedkeeper protocol and APDU exchanges
- **`satochip-android`**: bindings to use the satochip-lib with Android
- **`satochip-desktop`**: bindings to use the satochip-lib with Computer (Windows/Linux/Mac)

### Key Classes

- **`SatochipCommandSet`**: Main interface for sending commands to cards
- **`CardChannel`**: Abstraction for communication channel
- **`CardListener`**: Interface for handling card connection events
- **`NFCCardManager`**: Manages NFC card connections (for Android)
- **`APDUCommand`/`APDUResponse`**: Low-level command/response objects
- **`SatochipParser`**: Helper class used to parse APDUResponse returned by the card

## Basic Usage Flow

### 1. Implement CardListener

```java
public class MyCardHandler implements CardListener {
    
    @Override
    public void onConnected(CardChannel channel) {
        SatochipCommandSet commandSet = new SatochipCommandSet(channel);
        
        try {
            // Select the appropriate applet
            APDUResponse response = commandSet.cardSelect("satochip");
            
            if (response.isOK()) {
                // Perform card operations
                handleCardOperations(commandSet);
            }
        } catch (Exception e) {
            // Handle errors
        }
    }
    
    @Override
    public void onDisconnected() {
        // Handle disconnection
    }
}
```

### 2. Setup NFC Manager

```java
public class MainActivity extends AppCompatActivity {
    private NFCCardManager cardManager;
    private NfcAdapter nfcAdapter;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Initialize NFC components
        cardManager = new NFCCardManager();
        cardManager.setCardListener(new MyCardHandler());
        cardManager.start();
        
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        nfcAdapter.enableReaderMode(
            this,
            cardManager,
            NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_NFC_B,
            null
        );
    }
}
```

### 3. Basic Card Operations

The commands supported by the libraries are defined in the `SatochipCommandSet` class.
More details are provided in [CommandSet.md](./CommandSet.md).

```java
private void handleCardOperations(SatochipCommandSet commandSet) throws Exception {
    // Get card status
    APDUResponse statusResponse = commandSet.cardGetStatus();
    ApplicationStatus status = commandSet.getApplicationStatus();
    
    // Verify PIN if required
    byte[] pin = "123456".getBytes(StandardCharsets.UTF_8);
    commandSet.cardVerifyPIN(pin);
    
    // Perform specific operations based on card type
    // (see command reference below)
}
```

### 4. APDU Response parsing

The card returns a result in the form of an APDUResponse that includes a 2-bytes Status Word
(see [StatusWord.md](./StatusWord.md)) and a data byte array that can be parsed using the `SatochipParser` class.
More details are provided in [ApduParsing.md](./ApduParsing.md).

## Best Practices

1. **Always handle exceptions**: NFC communication can be unreliable
2. **Cache PIN securely**: Avoid repeated PIN prompts
3. **Verify card authenticity**: Use `cardVerifyAuthenticity()` for production apps
4. **Implement proper state management**: Track card connection state

## Additional Resources

- [Satochip GitHub Repository](https://github.com/Toporin/SatochipApplet)
- [Satodime GitHub Repository](https://github.com/Toporin/Satodime-Applet)
- [Seedkeeper GitHub Repository](https://github.com/Toporin/Seedkeeper-Applet)
- [Green Android Fork with Satochip Support](https://github.com/Toporin/green_android/tree/satochip-support)
- [Satodime Android Application](https://github.com/Toporin/Satodime-Android)
- [Seedkeeper Android Application](https://github.com/Toporin/Seedkeeper-Android)
---

This documentation covers the core functionality of the Satochip-Java library.
For specific use cases or advanced features, refer to the example implementations in the Green Android repository.