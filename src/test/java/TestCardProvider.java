import apdu4j.HexUtils;
import org.esteid.jca.CardDelegate;
import org.esteid.jca.DelegatingProvider;
import org.esteid.jca.NotificationInterface;
import org.junit.Ignore;
import org.junit.Test;

import javax.net.ssl.X509KeyManager;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;

public class TestCardProvider {

    public static final NotificationInterface CONSOLE = new NotificationInterface() {
        @Override
        public void showControlCode(String code) {
            System.out.println("Control code: " + code);
        }

        @Override
        public String askPinCode(String info) {
            if (info.indexOf("PIN2") != -1) {
                return "12345";
            }
            return "1234";
        }
    };

    @Test
    @Ignore
    public void testCardProvider() throws Exception {
        DelegatingProvider cp = DelegatingProvider.fromDelegate(CardDelegate.any(false, CONSOLE));
        Security.insertProviderAt(cp, 0);
        X509KeyManager km = cp.getKeyManager();

        String alias = km.chooseClientAlias(new String[]{"RSA"}, null, null);
        PrivateKey pk = km.getPrivateKey(alias);
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(pk);
        s.update(HexUtils.hex2bin("311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02"));
        byte[] result = s.sign();
        System.out.println(HexUtils.bin2hex(result));
    }
}
