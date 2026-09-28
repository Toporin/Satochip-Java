# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file covers the whole repository. Entries before 0.3.4 describe `satochip-lib` only, which is
where this changelog previously lived.

## [0.3.4]:

Java 17 support. The build now runs on JDK 17 (Gradle 4.10.2 -> 8.10, Android Gradle Plugin
3.2.1 -> 8.5.2), while the published bytecode stays at Java 11, so existing consumers are
unaffected. One behavioural fix was required, listed first because it affects card verification at
runtime.

* Fix `cardVerifyAuthenticity()` on JDK 16 and later. The `SunEC` provider dropped secp256k1 in
  JDK 16, and the bundled sub-CA certificates are secp256k1, so PKIX validation of the device
  certificate failed. `PKIXParameters.setSigProvider("BC")` now pins certificate-path signature
  verification to BouncyCastle, which still supports the curve. No other crypto path was affected:
  every other call site is either pinned to `"BC"` explicitly or uses BouncyCastle's lightweight
  API, which never consults the JCE provider list.
* Pin the compiled bytecode level. `satochip-lib` and `satochip-desktop` previously set no
  `targetCompatibility` at all, so the published class-file version silently followed whichever JDK
  built them. Both now compile with `options.release = 11` regardless of the build JDK, and the
  build itself requires JDK 17.
* Expose BouncyCastle as an `api` dependency. `SatochipParser.Recover()` returns
  `org.bouncycastle.math.ec.ECPoint`, but BouncyCastle was an `implementation` dependency and so
  landed in `runtime` scope in the published POM, meaning external callers of `Recover()` could not
  compile against it without declaring BouncyCastle themselves.
* Upgrade BouncyCastle to `bcprov-jdk18on:1.78`, replacing the 2018-era `bcprov-jdk15on:1.60`, and
  exclude the `bcprov-jdk15to18:1.69` copy that arrived transitively through bitcoinj. The two
  artifact IDs cannot be deduplicated by Gradle, so both sets of `org.bouncycastle` packages were
  previously on the classpath at once.
* Unify the version and group across all three modules. `satochip-android` previously pinned its
  own `version='0.0.2'` and `group='org.satochip'`, so it now tracks the repository version and
  sits under `com.github.Toporin.Satochip-Java` with its siblings. The module is not published, so
  no released coordinates change.
* `satochip-android`: `compileSdk` 28 -> 34, and the manifest `package` attribute is replaced by
  the `namespace` DSL, both required by AGP 8. `minSdk` stays at 19.

Known limitation on JDK 8 and JDK 11 runtimes, not introduced by this release: current builds of
both reject the certificate chain outright with `Algorithm constraints check failed on disabled
algorithm: secp256k1`. A JDK security update added secp256k1 to the `jdk.disabled.namedCurves`
property, which `jdk.certpath.disabledAlgorithms` pulls in via `include`, and that change was
backported to the 8u and 11.0.x update streams. The rejection happens in the PKIX algorithm-
constraints checker before any provider is selected, so `setSigProvider("BC")` cannot help.
`cardVerifyAuthenticity()` therefore worked on older 8 and 11 builds and stopped working when that
policy arrived. Verified here on 8u504 and 11.0.32 (both fail) against 17 and 21 (both ship the
property commented out, and both validate once the fix above is applied).

On JDK 17 or 21 no workaround is needed. On 8 or 11 the curve has to be re-enabled at the JVM level,
for example:

```
java -Djava.security.properties=enable-secp256k1.props ...
```

where that file contains `jdk.disabled.namedCurves=` (empty). Both this and dropping the
`include jdk.disabled.namedCurves` line from `jdk.certpath.disabledAlgorithms` were confirmed to
restore validation on 11.0.32.

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