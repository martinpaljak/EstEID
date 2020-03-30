package org.esteid;

import apdu4j.HexUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

// Access via javax.smartcardio
public class DesktopEstEID {

    public static final Map<byte[], EstEID.CardType> knownATRs;

    static {
        Map<byte[], EstEID.CardType> atrs = new HashMap<>();
        atrs.put(HexUtils.hex2bin("3bfe9400ff80b1fa451f034573744549442076657220312e3043"), EstEID.CardType.MICARDO);
        atrs.put(HexUtils.hex2bin("3b6e00ff4573744549442076657220312e30"), EstEID.CardType.MICARDO);
        atrs.put(HexUtils.hex2bin("3bde18ffc080b1fe451f034573744549442076657220312e302b"), EstEID.CardType.MICARDO);
        atrs.put(HexUtils.hex2bin("3b5e11ff4573744549442076657220312e30"), EstEID.CardType.MICARDO);
        atrs.put(HexUtils.hex2bin("3b6e00004573744549442076657220312e30"), EstEID.CardType.DigiID);
        atrs.put(HexUtils.hex2bin("3bfe1800008031fe454573744549442076657220312e30a8"), EstEID.CardType.JavaCard2011);
        atrs.put(HexUtils.hex2bin("3bfe1800008031fe45803180664090a4162a00830f9000ef"), EstEID.CardType.JavaCard2011);
        atrs.put(HexUtils.hex2bin("3BFA1800008031FE45FE654944202F20504B4903"), EstEID.CardType.JavaCard2011); // Digi-ID 2017 ECC upgrade
        atrs.put(HexUtils.hex2bin("3BDB960080B1FE451F830012233F536549440F9000F1"), EstEID.CardType.IASECC2018);
        knownATRs = Collections.unmodifiableMap(atrs);
    }
}
