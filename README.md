# EstEID hacker &nbsp; [![Latest release](https://img.shields.io/github/release/martinpaljak/esteid.java/all.svg)](https://github.com/martinpaljak/esteid.java/releases)  [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.martinpaljak/esteid/badge.svg)](https://mvnrepository.com/artifact/com.github.martinpaljak/esteid) [![LGPL-3.0 licensed](https://img.shields.io/badge/license-LGPL-blue.svg)](https://github.com/martinpaljak/esteid.java/blob/master/LICENSE)

Java utility and source code for everything and anything related to [EstEID](https://esteid.org):

* [EstEID.java - host API](#esteidjava)

## Usage
* Fetch and build the software (requires Unix-like OS)

        git clone https://github.com/martinpaljak/esteidhacker.git
        cd esteidhacker
        ant

* In this README `esteid` is used as an alias for `java -jar esteid-app.jar`. `esteid.exe` can be used on Windows.


## Dependencies
* [apdu4j](https://github.com/martinpaljak/apdu4j) (MIT)
* [BouncyCastle](bouncycastle.org/java.html) JCE provider + PKIX (MIT)

## License
Mixed LGPL/MIT, please check individual files! Other options available upon request.

## Contact
* martin@martinpaljak.net

## Upcoming features
* Planned:
  * Pinpad support for PC/SC readers
* Wishlist:
  * A GUI maybe, not unlike qesteidutil?

## Components

### EstEID.java

Encapsulates all the APDU protocol knowledge and exposes high-level and meaningful API for making operations with the card (more precisely: on-card application). Can talk to any PC/SC terminal or somethig else exposed via `javax.smartcardio` CommandAPDU/ResponseAPDU pairs.

Exception handling:
* IOException when transmit fails
* EstEIDException when card protocol (or data formats) have unexpected situations
* WrongPINException when a passed in PIN is incorrect

Source: [EstEID.java](src/org/esteid/EstEID.java)

#### Similar projects
* https://github.com/sleepless/jesteid
  * Very verbose but educating to read. Parses a lot of data.
* http://blog.codeborne.com/2010/10/javaxsmartcardio-and-esteid.html
  * Simple sample on how to read personal data file.
* https://eid.eesti.ee/index.php/Sample_applications#Claims_application
  * Complete "ecosystem" sample but not easily re-usable.
* [esteid.c](https://github.com/martinpaljak/esteid.c)
  * :( not yet in code  
* [MOCCA](https://www.egiz.gv.at/en/schwerpunkte/9-MOCCA) - [EstEIDCard.java](https://joinup.ec.europa.eu/svn/mocca/trunk/smcc/src/main/java/at/gv/egiz/smcc/EstEIDCard.java) http://git.egiz.gv.at/mocca/
  * :) Java
  * :| ... messy

----
All about the [EstEID](https://esteid.org)
