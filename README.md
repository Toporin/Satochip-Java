# Satochip Java SDK for Android and Desktop

This SDK simplifies integration with the [Satochip](https://github.com/Toporin/SatochipApplet) and [Satodime](https://github.com/Toporin/Satodime-Applet) in Android
and Desktop applications. In this SDK you find both the classes needed for generic communication with SmartCards as well 
as classes specifically addressing the Satochip.

## Usage

Currently, you can import the different libraries in your Gradle project by placing the .jar library in a folder (e.g. 'libs')
and by adding the following line in the *dependencies* section of your *build.gradle* file:

```api files('libs/satochip-lib-0.0.3.jar')```

In the future, the library will also be available on Maven central repository.

## License and attribution

This project is based on the [status-keycard-java library](https://github.com/status-im/status-keycard-java) released under the Apache-2.0 License.