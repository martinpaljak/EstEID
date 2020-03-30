package org.esteid;

import javax.security.auth.callback.*;
import java.util.Map;

public class MockCallbackHandler implements CallbackHandler {

    private final Map<String, String> values;

    public MockCallbackHandler(Map<String, String> values) {
        this.values = values;
    }

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        for (Callback c : callbacks) {
            if (c instanceof PasswordCallback) {

                PasswordCallback pc = (PasswordCallback) c;
                if (values.containsKey(pc.getPrompt()))
                    pc.setPassword(values.get(pc.getPrompt()).toCharArray());
                else if (System.getenv().containsKey(pc.getPrompt())) {
                    pc.setPassword(System.getenv(pc.getPrompt()).toCharArray());
                } else
                    throw new UnsupportedCallbackException(c, "Don't have a value for " + pc.getPrompt());
            } else if (c instanceof TextOutputCallback) {
                System.out.println(((TextOutputCallback) c).getMessage());
            } else {
                throw new UnsupportedCallbackException(c, "Callback not supported");
            }
        }
    }
}
