import org.esteid.jca.NotificationInterface;
import org.esteid.jca.SmartIDDelegate;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class TestSmartID  {

    static String demoauth = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGszCCBJugAwIBAgIQMCRMRy9gjfNZ9xm9LzTerjANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQG\n" +
            "EwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEXMBUGA1UEYQwOTlRSRUUt\n" +
            "MTA3NDcwMTMxHDAaBgNVBAMME1RFU1Qgb2YgRUlELVNLIDIwMTYwHhcNMTcxMDMwMTIyMzI1WhcN\n" +
            "MjAxMDMwMTIyMzI1WjB1MQswCQYDVQQGEwJFRTEoMCYGA1UEAwwfUEFMSkFLLE1BUlRJTixQTk9F\n" +
            "RS0zODIwNzE2MjcyMjEPMA0GA1UEBAwGUEFMSkFLMQ8wDQYDVQQqDAZNQVJUSU4xGjAYBgNVBAUT\n" +
            "EVBOT0VFLTM4MjA3MTYyNzIyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjh2rVV81\n" +
            "MYMziM0WEDGcrGOL3jUJiKaZ0i+6rU+BfyuF/Hyo+4rYt4DZYdi9uscjrzm2OE5V9EYPePu09lE7\n" +
            "giFAosdXp0xT3lDXuwlasMShz34TXx6gUCLIemOS0a81p2TJJp5ab9Uxv+Q0VlmA8+h1XjK1TORg\n" +
            "fF2+ycSJ1Xa52M4gZ+Z32TAtPlISCOfrbFGSGkUkLumVIIG+lMh3xIWYppQLPRN9rsVPGYdjXxN8\n" +
            "sm5iEGR58AVgs2GtQQR6sqZlerBT3+eMzhdh8DpbENnOUY/ZA/S29kH1iUHZjbK7jDCFu6w0lTg2\n" +
            "31RGGQT4i6t9IHk7Gap0m5/ZV7jThnHnbxjfBJQUNPpWGFfGeWI3LmsbwQqfhRYaDiEMvHsBg3+y\n" +
            "vMDW/SsE44VXpRRpVrqBfbWWwPz1qzXy2THAho3SdaJvnToszb/Mn9bc9IQUbHMp2SBxCkt48PR7\n" +
            "EhASYv9cGVxfdKb1jdR6IXVv3kPPNUN4eCtLQIaAFfbht62LwpDgEA1C2zDxSUqMnSw37K2B8ELB\n" +
            "7ttDbbj+ppnVZu8hqWju3kaekWR0TOYATzzHkQFDJZuC3DoOUQK3qDfBfi1U9UbUdswnvM1Xc3jE\n" +
            "TcJ0hqa++9HLInBd0sJfIVh75cEOFBYz7WtDsUNBrRqWt6nZr2PGaW/FzDhGaiPpaqsCAwEAAaOC\n" +
            "AUowggFGMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgSwMFUGA1UdIAROMEwwQAYKKwYBBAHOHwMR\n" +
            "AjAyMDAGCCsGAQUFBwIBFiRodHRwczovL3d3dy5zay5lZS9lbi9yZXBvc2l0b3J5L0NQUy8wCAYG\n" +
            "BACPegEBMB0GA1UdDgQWBBS8jsrNlDt1Sn4AdVdg0HtZd9H5wzAfBgNVHSMEGDAWgBSusOrhNvgm\n" +
            "q6XMC2ZV/jodAr8StDATBgNVHSUEDDAKBggrBgEFBQcDAjB9BggrBgEFBQcBAQRxMG8wKQYIKwYB\n" +
            "BQUHMAGGHWh0dHA6Ly9haWEuZGVtby5zay5lZS9laWQyMDE2MEIGCCsGAQUFBzAChjZodHRwczov\n" +
            "L3NrLmVlL3VwbG9hZC9maWxlcy9URVNUX29mX0VJRC1TS18yMDE2LmRlci5jcnQwDQYJKoZIhvcN\n" +
            "AQELBQADggIBABskNFJfq7POzZAcyWYG/ZyyJqTx3SfuoV6rb60hA+pZ+m0R7yYBxv9tO3Eb4T/R\n" +
            "LE2MxIq0c76k1HtTu+jYsACcm1B1OhhVT9/zqZME/EHr/ANyp2mqLlNRw3NVun5PJ2PUEQeO8VA6\n" +
            "DRzbywb5BOiWezB1WoW23pTZz5AO9KuUm7O/C/koTxuE9Z3p5Fl5TcYBKrkZIqexQOdClfQO2swY\n" +
            "DKFKvc5soKr1ODJVBmBRphI0NyoSE57gGLN3v66uN3TziZoNGwHJTpF5T/clozGxjU3VkOX1hGNC\n" +
            "scHxJvDyMnEPCuzuVV9Fk29zaQ0F4mUBYZPgLFCf/WO0gflZZxZBRKNcaLNtORr9nZeRS/QmGgSB\n" +
            "fmPJ9pBNO3n26EtWz4IqlUugJyR44O4aJtKRRdmYy3iPJtx5etY80lVzOIFEcYKxVBoOfZhIEc7+\n" +
            "6DVGthMYQ5G+C5I8NlARFSJ2dvOFcyQAEWO2+3ZBQLC4eAsRIUNyhdZULx9TKLiDsCtVwehipQbA\n" +
            "DV4F6HDN9oCB0g2l7QjiZkmcJrMyJqQlB47s+QgwF0dlhqFaB/QkRGuPLH+YovLb7ypM3jJSNzlK\n" +
            "A4NEQhXrE3nNb27tU8/wm1Zb5ZvZ4Zri6baIBT0Sm/rKRVSuehW7a4LhxiNfweL02OH8lsUiqTYh\n" +
            "qaGvGkzF26V2\n" +
            "-----END CERTIFICATE-----";

    static final X509Certificate crt;
    static  {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            crt = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(demoauth.getBytes()));
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Can not parse cert", e);
        }
    }
    @Test
    public void testSomething() throws Exception {

        SmartIDDelegate sis = SmartIDDelegate.withFixedCertificate(null, null, crt, SmartIDDelegate.CONSOLE);
       // if (1==1) return;

        //SmartIDCallbacks smartid = new SmartIDCallbacks("1d1b50c7-7f82-47fa-aa47-ee171c646afd", "isikukood.ee", "EE", "38207162722", false);

       // SmartIDCallbacks smartid = new SmartIDCallbacks("1d1b50c7-7f82-47fa-aa47-ee171c646afd", "isikukood.ee", "EE", "38207162722", false, console);

       // X509Certificate cert = smartid.readCertificate();
       // byte[] signature = smartid.getSignature(HexUtils.hex2bin("311fe3feed16b9cd8df0f8b1517be5cb86048707df4889ba8dc37d4d68866d02"));

       // Signature sig = Signature.getInstance("SHA256withRSA");
       // sig.initVerify(cert);
       // System.out.println("Verify: " + sig.verify(signature));
    }
}
