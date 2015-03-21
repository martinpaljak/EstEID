# EstEID hacker

Java ~~utilities~~ source code for everything and anything related to [EstEID](http://esteid.org):

* [EstEID.java](src/esteidhacker/EstEID.java) - javax.smartcardio helper for any EstEID-compatible card with a high-level interface for certificates, crypto, PIN codes and personal data file.
* [FakeEstEID.java](src/esteidhacker/FakeEstEID.java) - utility for working with a [FakeEstEIDApplet](https://github.com/martinpaljak/AppletPlayground/wiki/FakeEstEID) instance. Supports emulation inside [vJCRE](https://github.com/martinpaljak/vJCRE#import-projavacardvre).
* [FakeEstEIDCA.java](src/esteidhacker/FakeEstEIDCA.java) - utility for maintaining a [SK](http://www.sk.ee) look-alike CA for [EstEID related certificates](https://www.sk.ee/repositoorium/sk-sertifikaadid/) (root, esteid, user auth/sign).
* [CLI.java](src/esteidhacker/CLI.java) - code of the command line utility that serves as usage documentation.

## Usage
* Fetch and build the software (requires Unix-like OS)

        git clone https://github.com/martinpaljak/esteidhacker.git
        cd esteidhacker
        ant

* Create a new FakeEstEID card (requires a [supported JavaCard](https://github.com/martinpaljak/GlobalPlatform/wiki/TestedCards)):
        
        java -jar esteid.jar -install -ca fake.ca -new

* Run EstEID test-suite against a real card (via PC/SC):

        $ java -jar esteid.jar -info -test-crypto -pin1 XXXX -pin2 YYYYY 
        ATR:  3BFE1800008031FE45803180664090A4162A00830F9000EF
        Type: JavaCard2011
        PIN tries remaining: PIN1: 3; PIN2: 3; PUK: 1;
        Doc#: AA0448165
        Cardholder: MARTIN PALJAK
        Certificate subject: C=EE,O=ESTEID,OU=authentication,CN=PALJAK\,MARTIN\,38207162722,SURNAME=PALJAK,GIVENNAME=MARTIN,SERIALNUMBER=38207162722
        Auth cert C=EE,O=ESTEID,OU=authentication,CN=PALJAK\,MARTIN\,38207162722,SURNAME=PALJAK,GIVENNAME=MARTIN,SERIALNUMBER=38207162722
        ENCRYPT: OK
        DECRYPT: OK
        Sign cert C=EE,O=ESTEID,OU=digital signature,CN=PALJAK\,MARTIN\,38207162722,SURNAME=PALJAK,GIVENNAME=MARTIN,SERIALNUMBER=38207162722
        ENCRYPT: OK


* Run EstEID test-suite against a real test Digi-ID card (via PC/SC):

        $ java -jar esteid.jar -info -test
        ATR:  3BFE9400FF80B1FA451F034573744549442076657220312E3043
        Type: DigiID
        PIN tries remaining: PIN1: 3; PIN2: 3; PUK: 3;
        Doc#: N0000952
        Certificate subject: C=EE,O=ESTEID (DIGI-ID),OU=authentication,CN=ŽAIKOVSKI\,IGOR\,37101010021,SURNAME=ŽAIKOVSKI,GIVENNAME=IGOR,SERIALNUMBER=37101010021
        Auth cert C=EE,O=ESTEID (DIGI-ID),OU=authentication,CN=ŽAIKOVSKI\,IGOR\,37101010021,SURNAME=ŽAIKOVSKI,GIVENNAME=IGOR,SERIALNUMBER=37101010021
        ENCRYPT: OK
        DECRYPT: OK
        Sign cert C=EE,O=ESTEID (DIGI-ID),OU=digital signature,CN=ŽAIKOVSKI\,IGOR\,37101010021,SURNAME=ŽAIKOVSKI,GIVENNAME=IGOR,SERIALNUMBER=37101010021
        ENCRYPT: OK

* Run EstEID test-suite against an emulated card (read: test the FakeEstEIDApplet):
        
        $ java -jar esteid.jar -emulate -info -test
        ATR:  3B80800101
        Type: AnyJavaCard
        PIN tries remaining: PIN1: 3; PIN2: 3; PUK: 3;
        Doc#: A0000001
        Cardholder: SIILIPOISS JÄNES-KARVANE
        Certificate subject: C=EE,O=ESTEID,OU=authentication,CN=UDUS\,SIILIPOISS\,10101010005,SURNAME=UDUS,GIVENNAME=SIILIPOISS,SERIALNUMBER=10101010005
        Auth cert C=EE,O=ESTEID,OU=authentication,CN=UDUS\,SIILIPOISS\,10101010005,SURNAME=UDUS,GIVENNAME=SIILIPOISS,SERIALNUMBER=10101010005
        ENCRYPT: OK
        DECRYPT: OK
        Sign cert C=EE,O=ESTEID,OU=digital signature,CN=UDUS\,SIILIPOISS\,10101010005,SURNAME=UDUS,GIVENNAME=SIILIPOISS,SERIALNUMBER=10101010005
        ENCRYPT: OK


* Clone a card

	$ java -jar esteid.jar -clone


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

## Upcoming features
* Planned:
  * Pinpad support for PC/SC readers
* Wishlist:
  * A GUI maybe, not unlike qesteidutil?

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
