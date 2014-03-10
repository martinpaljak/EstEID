# EstEID hacker

Java ~~utilities~~ source code for everything/anything related to EstEID:

* [EstEID.java](src/esteidhacker/EstEID.java) - javax.smartcardio wrapper for any EstEID-compatible card with a high-level interface for crypto, PIN-s and personal data file.
* [FakeEstEID.java](src/esteidhacker/FakeEstEID.java) - utility for working with a [FakeEstEIDApplet](https://github.com/martinpaljak/AppletPlayground/wiki/FakeEstEID) instance, also in [vJCRE](https://github.com/martinpaljak/vJCRE#import-projavacardvre)
* [FakeEstEIDCA.java](src/esteidhacker/FakeEstEIDCA.java) - utility for maintaining a [SK](http://www.sk.ee) look-alike CA for [EstEID related certificates](https://www.sk.ee/repositoorium/sk-sertifikaadid/) (root, esteid, auth/sign).


## Usage 
* Create new FakeEstEID card:
        
        java -jar esteid.jar -ca fake.ca -new

* Run EstEID test-suite against a real card:

        java -jar esteid.jar -test

* Run EstEID test-suite against an emulated card (test the FakeEstEIDApplet):

        java -jar esteid.jar -test -emulated

## License
Mixed LGPL/MIT, check individual files!

## Dependencies
* FakeEstEIDApplet
* vJCRE
* GlobalPlatform
  * jnasmartcardio
* BouncyCastle

## Similar projects
EstEID card access through javax.smartcardio

* https://github.com/sleepless/jesteid
  * Very verbose but interesting to read. Parses a lot of data.
* http://blog.codeborne.com/2010/10/javaxsmartcardio-and-esteid.html
  * Simple sample on how to read personal data file.
* https://eid.eesti.ee/index.php/Sample_applications#Claims_application
  * Complete "ecosystem" sample but not easily re-usable.

----
All about the [EstEID](http://esteid.org)
