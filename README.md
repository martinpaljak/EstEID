# EstEID hacker

Java ~~utilities~~ source code for everything related to EstEID:

* [EstEID.java](src/esteidhacker/EstEID.java) - javax.smartcardio wrapper for any EstEID-compatible card with a high-level interface.
* [FakeEstEID.java](src/esteidhacker/FakeEstEID.java) - utility for working with a [FakeEstEIDApplet](https://github.com/martinpaljak/AppletPlayground/wiki/FakeEstEID) instance.
* [FakeEstEIDCA](src/esteidhacker/FakeEstEIDCA.java) - utility for maintaining a [SK](http://www.sk.ee) look-alike CA for [EstEID related certificates](https://www.sk.ee/repositoorium/sk-sertifikaadid/) (root, esteid, auth/sign).

## License
Mixed LGPL/MIT, check individual files!

## Similar projects
* https://github.com/sleepless/jesteid
* http://blog.codeborne.com/2010/10/javaxsmartcardio-and-esteid.html

----
All about the [EstEID](http://esteid.org)
