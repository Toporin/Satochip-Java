# Satochip Java SDK for Android and Desktop

This SDK simplifies integration with the [Satochip](https://github.com/Toporin/SatochipApplet) and [Satodime](https://github.com/Toporin/Satodime-Applet) in Android
and Desktop applications. In this SDK you find both the classes needed for generic communication with SmartCards as well 
as classes specifically addressing the Satochip.

## Modules

| Module | Contents |
|---|---|
| `satochip-lib` | the core library: `SatochipCommandSet`, the secure channel, APDU types, SeedKeeper support. No platform dependencies. |
| `satochip-desktop` | `PCSCCardChannel`, the `javax.smartcardio` binding for desktop JVMs. Depends on `satochip-lib`. |
| `satochip-android` | `NFCCardManager` / `NFCCardChannel` for Android. Needs the Android SDK to build. |

## Building

### Requirements

* **JDK 8 or 11.** The build uses Gradle 4.10.2, which does not run on JDK 17 or later.
  Use `sudo update-alternatives --config java` to switch, or set `JAVA_HOME` for one invocation:
  ```
  JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64 ./gradlew ...
  ```
* Building `satochip-android` additionally needs the Android SDK, with its location in
  `local.properties` (`sdk.dir=/path/to/Android/Sdk`). The two JVM modules build without it.

### Commands

```
./gradlew :satochip-lib:jar          # build the core library jar
./gradlew :satochip-desktop:jar      # build the desktop binding
./gradlew clean build                # everything, including satochip-android
```

Jars land in `<module>/build/libs/`.

The version is set in `gradle.properties` and can be overridden per invocation with
`-Pversion=<version>`.

## Usage

### From JitPack (recommended)

```groovy
repositories {
    maven { url 'https://jitpack.io' }
}

dependencies {
    // desktop: pulls satochip-lib transitively
    implementation 'com.github.Toporin.Satochip-Java:satochip-desktop:<tag>'
    // or the core library alone, e.g. on Android
    implementation 'com.github.Toporin.Satochip-Java:satochip-lib:<tag>'
}
```

`<tag>` is a git tag of this repository, or a commit hash.

### From a local jar

Place the jar in a folder (e.g. `libs`) and add to the *dependencies* section of your
*build.gradle*:

```groovy
api files('libs/satochip-lib-0.2.6.jar')
```

To install into your local Maven repository instead:

```
./gradlew :satochip-lib:publishToMavenLocal :satochip-desktop:publishToMavenLocal
```

## Compatibility notes

The library talks to three different applets (Satochip, SeedKeeper, Satodime), whose APDU
interfaces are versioned independently. Where a command's format changed, the library selects the
right one from the applet type and the protocol version reported by GET STATUS, both cached after
the first `cardSelect()`/`cardGetStatus()`. The current case is `cardUnblockPin()`: Satochip
applet v0.16 introduced a length-prefixed payload and the ability to set a new PIN while
unblocking, while earlier Satochip versions, SeedKeeper and Satodime keep the legacy bare-PUK
payload.

## License and attribution

This project is based on the [status-keycard-java library](https://github.com/status-im/status-keycard-java) released under the Apache-2.0 License.