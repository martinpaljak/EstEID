package org.esteid;

import apdu4j.APDUBIBO;
import apdu4j.BIBO;
import apdu4j.CardBIBO;
import apdu4j.TerminalManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.SkipException;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class EstEIDIT {
    @BeforeClass
    public static void beforeClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testCardReading() throws Exception {
        APDUBIBO bibo = (APDUBIBO) getBIBO().orElseThrow(() -> new SkipException("No EstEID"));
        EstEID esteid = new EUREstEID(bibo);

        System.out.println(esteid.getAuthenticationCertificate().getSubjectX500Principal().toString());
        System.out.println(esteid.getSigningCertificate().getSubjectX500Principal().toString());

        UICallbackHandler ui = new UICallbackHandler();
        EstEIDSelfTests test = new EstEIDSelfTests(esteid, ui);
        test.crypto_tests();
    }


    public static Optional<BIBO> getBIBO() {
        try {
            List<CardTerminal> readers = TerminalManager.byAID(Arrays.asList(EUREstEID.getAwpAid()));
            if (readers.size() == 0)
                return Optional.empty();
            return Optional.of(CardBIBO.wrap(readers.get(0).connect("*")));
        } catch (RuntimeException | CardException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return Optional.empty();
        }
    }
}
