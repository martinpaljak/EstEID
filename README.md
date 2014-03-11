# EstEID hacker

Java ~~utilities~~ source code for everything and anything related to EstEID:

* [EstEID.java](src/esteidhacker/EstEID.java) - javax.smartcardio helper for any EstEID-compatible card with a high-level interface for certificates, crypto, PIN codes and personal data file.
* [FakeEstEID.java](src/esteidhacker/FakeEstEID.java) - utility for working with a [FakeEstEIDApplet](https://github.com/martinpaljak/AppletPlayground/wiki/FakeEstEID) instance. Supports emulation inside [vJCRE](https://github.com/martinpaljak/vJCRE#import-projavacardvre).
* [FakeEstEIDCA.java](src/esteidhacker/FakeEstEIDCA.java) - utility for maintaining a [SK](http://www.sk.ee) look-alike CA for [EstEID related certificates](https://www.sk.ee/repositoorium/sk-sertifikaadid/) (root, esteid, user auth/sign).


## Usage
* Fetch and build the software (requires Unix-like OS)

      git clone https://github.com/martinpaljak/esteidhacker.git
      cd esteidhacker
      ant

* Create a new FakeEstEID card (requires a supported JavaCard):
        
      java -jar esteid.jar -ca fake.ca -new

* Run EstEID test-suite against a real card (via PC/SC):

      java -jar esteid.jar -test

* Run EstEID test-suite against an emulated card (read: test the FakeEstEIDApplet):

      java -jar esteid.jar -emulate -new -test

## Dependencies
* [FakeEstEIDApplet](https://github.com/martinpaljak/AppletPlayground/wiki/FakeEstEID) from [AppletPlayground](https://github.com/martinpaljak/AppletPlayground#applet-playground) (MIT)
* [vJCRE](https://github.com/martinpaljak/vJCRE#import-projavacardvre) (LGPL)
* [GlobalPlatform](https://github.com/martinpaljak/GlobalPlatform#globalplatform-from-openkms) (LGPL)
  * includes [jnasmartcardio](https://github.com/martinpaljak/jnasmartcardio) (CC0 / public domain)
* [BouncyCastle](bouncycastle.org/java.html) JCE provider + PKIX (MIT)

## License
Mixed LGPL/MIT, please check individual files! Other options available upon request.


## Contact

* martin@martinpaljak.net


## Similar projects
EstEID card access through javax.smartcardio

* https://github.com/sleepless/jesteid
  * Very verbose but educating to read. Parses a lot of data.
* http://blog.codeborne.com/2010/10/javaxsmartcardio-and-esteid.html
  * Simple sample on how to read personal data file.
* https://eid.eesti.ee/index.php/Sample_applications#Claims_application
  * Complete "ecosystem" sample but not easily re-usable.

----
All about the [EstEID](http://esteid.org)
