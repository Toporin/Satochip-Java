# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2]:

Add Schnorr signature & Musig2 signature support for Satochip:
* byte[] cardTaprootTweakPrivateKey(int keynbr, byte[] tweak, Boolean bypass_flag)
* byte[] cardSignSchnorrHash(byte[] txhash, byte[] chalresponse)
* byte[][] cardMusig2GenerateNonce(int keynbr, byte[] aggpk, byte[] msg, byte[] extra)
* byte[] cardMusig2Sign(int keynbr, byte[] secnonce, byte[] b, byte[] ea, Boolean r_has_even_y, Boolean ggacc_is_1)

## [0.3.1]:

* Add Satocash support (wip)

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