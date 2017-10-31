import org.apache.commons.io.IOUtils;
import org.esteid.jca.AbstractDelegate;
import org.esteid.jca.DelegatingProvider;
import org.esteid.jca.CardDelegate;
import org.esteid.jca.SmartIDDelegate;
import org.junit.Ignore;
import org.junit.Test;

import javax.net.ssl.*;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

public class TestTls {

    @Test
    @Ignore
    public void testTlsWithSmartID() throws Exception {
        URL url = new URL("https://localhost:4433");
        X509Certificate mycert = TestSmartID.crt;
        DelegatingProvider cp = DelegatingProvider.fromDelegate(SmartIDDelegate.forPerson("1d1b50c7-7f82-47fa-aa47-ee171c646afd", "isikukood.ee", "EE", "38207162722", false, SmartIDDelegate.CONSOLE));
        //CallbackProvider cp = CallbackProvider.fromDelegate(SmartIDCallbacks.withFixedCertificate("1d1b50c7-7f82-47fa-aa47-ee171c646afd", "isikukood.ee", mycert, TestSmartID.console));
        Security.insertProviderAt(cp, 0);

        SSLContext ssl = SSLContext.getInstance("TLSv1.2");
        ssl.init(new KeyManager[]{cp.getKeyManager()}, new TrustManager[]{AbstractDelegate.DUMMY}, new SecureRandom());
        connectAndDump(ssl, url);
    }

    @Test
    @Ignore
    public void testTlsWithCard() throws Exception {
        URL url = new URL("https://localhost:4433");
        //URL url = new URL("https://www.eesti.ee/idportaal/login.html");
        DelegatingProvider cp = DelegatingProvider.fromDelegate(CardDelegate.any(true, TestCardProvider.CONSOLE));
        Security.insertProviderAt(cp, 0);

        SSLContext ssl = SSLContext.getInstance("TLSv1.2");
        ssl.init(new KeyManager[]{cp.getKeyManager()}, new TrustManager[]{AbstractDelegate.DUMMY}, new SecureRandom());
        connectAndDump(ssl, url);
    }

    private void connectAndDump(SSLContext ssl, URL url) throws Exception {
//        for (Provider p: Security.getProviders()) {
//            System.out.println("Provider: " + p.getName());
//            for (Provider.Service s: p.getServices()) {
//                System.out.println("   " + s.getType() + "." + s.getAlgorithm());
//            }
//        }
        SSLSocketFactory factory = ssl.getSocketFactory();

        HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
        con.setSSLSocketFactory(factory);

        System.out.println("Got HTTP " + con.getResponseCode());
        for (Map.Entry<String, List<String>> e : con.getHeaderFields().entrySet()) {
            System.out.println("Header: " + e.getKey() + " is " + e.getValue().get(0));
        }
        try (InputStreamReader in = new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8)) {
            IOUtils.copy(in, System.out, "UTF-8");
        } catch (SSLHandshakeException e) {
            throw new RuntimeException("Could not connect", e);
        }
    }
}
