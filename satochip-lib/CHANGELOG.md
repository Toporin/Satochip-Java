# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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