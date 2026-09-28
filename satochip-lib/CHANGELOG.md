# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.6]:

* Fix `cardUnblockPin()` for Satochip applet v0.16: the applet changed the UNBLOCK PIN data format to `[PUK_size(1b) | PUK | (optional) PIN_size(1b) | PIN]`, but the library still sent the bare PUK with no length prefix, so unblocking a v0.16 Satochip always failed. The format is now selected from the applet type and the protocol version reported by GET STATUS (cached after the first select): Satochip v0.16 and later get the length-prefixed payload, while earlier Satochip versions, SeedKeeper and Satodime keep the legacy bare-PUK payload.
* Add `cardUnblockPin(byte[] puk, byte[] newPin)`, which unblocks a PIN and replaces it in one command, as allowed by Satochip v0.16. Passing a new PIN to an applet that does not support it throws `IllegalArgumentException` rather than sending a payload the card would misparse. The existing single-argument `cardUnblockPin(byte[] puk)` is unchanged for callers and keeps the previous PIN.
* Fix an intermittent failure in every command that recovers a public key from a signature, including `cardInitiateSecureChannel()`. `parseToCompactSignature()` accepted a DER INTEGER only at length 0x20 or 0x21 and threw "Wrong signature r/s length" otherwise, but DER is minimally encoded: a value below 2^248 is emitted in fewer than 32 bytes, which happens for about one signature component in 256. Measured against a simulated card, `cardInitiateSecureChannel()` failed roughly 1% of the time before the fix and 0 times in 2000 attempts after it. Integers of any length up to 32 bytes are now right-aligned and zero-padded.
* Fix a potential `NullPointerException` in `recoverPubkey()` and `recoverRecId()`: `Recover()` returns null for a recovery id that yields no point on the curve, and the result was dereferenced without a check. `recoverPossiblePubkeys()` already guarded against this.
* Add `SatochipCommandSet.getCardType()`, returning the applet type selected on the card ("satochip", "seedkeeper", "satodime", "unknown", or null before the first select).
* Fix `ApplicationStatus.getProtocolVersion()` for minor versions of 0x80 or above: the version bytes were sign-extended when packed into an int, which would have made version comparisons negative and therefore wrong. Values below 0x80, which is every released version so far, are unaffected.
* Publish `satochip-lib` and `satochip-desktop` to JitPack. Previously neither module declared a group or a version, so JitPack published only a 3 KB `satochip-desktop` jar containing `PCSCCardChannel`, and `SatochipCommandSet` was not available to consumers at all. Also replace `jcenter()`, sunset in 2021, with `mavenCentral()`.

## [0.2.5]:

Support for Satodime v0.2:
* Add SatodimeStatus fixedCvc & isCoa fields and getter

## [0.2.4]:

* Improve javadoc, minor code refactor.

## [0.2.3]:

* Return default values instead of throwing for unsupported values in SeedkeeperExportRights, SeedkeeperSecretOrigin, SeedkeeperSecretType

## [0.2.2]:

* Add Exception related to PIN mgmt in cardVerifyPin, cardChangePin & cardUnblockPin 
* Note: this release breaks changeCardPin() compatibility.

## [0.2.1]:

* Application status: add getCardVersionString() function
* patch: remove sensitive info from logs

## [0.2.0]:

* feature: card get label, change pin and update card label implemented
* recover list of authentikeys from cardInitiateSecureChannel()

## [0.1.0]:

* Add Seedkeeper support

## [0.0.4]:

* Add logging support.
Using setLoggerLevel() method of SatochipCommandSet class, the level of logging can be defined.

## [0.0.3]:

* patch minor issue: only increase unlock_counter if sensitive APDU succeeds