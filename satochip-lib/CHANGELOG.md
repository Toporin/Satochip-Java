# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.3]:

Merges the Schnorr/MuSig2 and Satocash support from 0.3.1-0.3.2 with the PIN and
signature-parsing fixes from 0.2.6. No API was removed; the two lines of development touched
different commands.

* Make the Schnorr/Taproot/MuSig2 commands public. `cardTaprootTweakPrivateKey()`,
  `cardMusig2GenerateNonce()` and `cardMusig2Sign()` were declared private in 0.3.2 with no public
  wrapper, so the feature the 0.3.2 notes advertise was unreachable from outside the library: only
  `cardSignSchnorrHash()` was public, and it needs a prior taproot tweak.
* Fix `cardTaprootTweakPrivateKey()` for BIP86 key-path-only spending. It required a 32-byte tweak,
  but Satochip v0.16 expects `tweak_size = 0` when the output commits to no script tree, and the
  two are **not** interchangeable: BIP341 hashes `x(P)` alone in the first case and
  `x(P) || 32 zero bytes` in the second, producing a different output key. A client sending 32 zero
  bytes to mean "no script tree" would therefore derive the wrong address. `tweak` may now be
  `null` (or empty) for `tweak_size = 0`; any length other than 0 or 32 is rejected.
  Verified on a simulated v0.16 card: both forms produce signatures that verify against an
  independent BIP340 verifier, and the two output keys differ as the specification requires.
* `cardUnblockPin()` keeps the applet-aware behaviour introduced in 0.2.6 (see below): Satochip
  v0.16 and later get the length-prefixed payload, everything else keeps the legacy one.
* The DER signature-parsing fix from 0.2.6 also benefits the new Schnorr and MuSig2 commands, which
  parse card signatures through the same code path.

## [0.3.2]:

Add Schnorr signature & Musig2 signature support for Satochip:
* byte[] cardTaprootTweakPrivateKey(int keynbr, byte[] tweak, Boolean bypass_flag)
* byte[] cardSignSchnorrHash(byte[] txhash, byte[] chalresponse)
* byte[][] cardMusig2GenerateNonce(int keynbr, byte[] aggpk, byte[] msg, byte[] extra)
* byte[] cardMusig2Sign(int keynbr, byte[] secnonce, byte[] b, byte[] ea, Boolean r_has_even_y, Boolean ggacc_is_1)

## [0.3.1]:

* Add Satocash support (wip)
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