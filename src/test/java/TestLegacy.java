import apdu4j.HexUtils;
import org.esteid.EstEID;
import org.esteid.Legacy;
import org.junit.Assert;
import org.junit.Test;

import java.util.Map;

public class TestLegacy {
    @Test
    public void testEnvelopeGeneration() {
        // EstEID kaardi kasutusjuhend, 17.1
        byte[] cmk1 = HexUtils.hex2bin("A1A1A1A1A1A1A1A1A2A2A2A2A2A2A2A2");
        // http://www.id.ee/index.php?id=30379
        Map<String, String> pins = Legacy.pins_from_cmk_and_envelope(cmk1, "00000000001");
        Assert.assertEquals(EstEID.PIN1String, pins.get("PIN1"));
        Assert.assertEquals(EstEID.PIN2String, pins.get("PIN2"));
        Assert.assertEquals(EstEID.PUKString, pins.get("PUK"));
    }
}
