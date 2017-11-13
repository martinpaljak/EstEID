package org.esteid.hacker;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.esteid.hacker.CLI;
import org.esteid.hacker.FakeEstEIDCA;
import org.junit.Test;

import java.io.File;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

public class TestFakeCA {
    private static File cafile = new File("fake.ca");

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static FakeEstEIDCA generateOrLoadCA() throws Exception {
        FakeEstEIDCA ca = new FakeEstEIDCA();
        if (!cafile.exists()) {
            ca.generate();
            ca.storeToFile(cafile);
        } else {
            ca.loadFromFile(cafile);
        }
        return ca;
    }


    @Test
    public void testGenerateCA() throws Exception {
        FakeEstEIDCA ca = generateOrLoadCA();
    }

    @Test
    public void testGenerateECC() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair keyPair = kpg.generateKeyPair();

        FakeEstEIDCA ca = generateOrLoadCA();
        X509Certificate crt = ca.generateUserCertificate(keyPair.getPublic(), false, "MARTIN", "PALJAK", "38207162722", "martin.paljak@eesti.ee", new Date(), new Date());

        System.out.println(CLI.crt2pem(crt));
    }

    @Test
    public void testCloneECC() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair keyPair = kpg.generateKeyPair();

        FakeEstEIDCA ca = generateOrLoadCA();

        X509Certificate crt = ca.cloneUserCertificate(keyPair.getPublic(), FakeEstEIDCA.holder2pem(FakeEstEIDCA.getRealCert("sk-auth.pem")));
        System.out.println(CLI.crt2pem(crt));

    }
}
