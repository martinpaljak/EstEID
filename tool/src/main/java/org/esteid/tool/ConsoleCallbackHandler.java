package org.esteid.tool;

import javax.security.auth.callback.*;

public class ConsoleCallbackHandler implements CallbackHandler {

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        for (Callback c : callbacks) {
            if (c instanceof PasswordCallback) {
                PasswordCallback pc = (PasswordCallback) c;
                if (System.getenv().containsKey(pc.getPrompt())) {
                    pc.setPassword(System.getenv(pc.getPrompt()).toCharArray());
                } else if (System.console() != null) {
                    pc.setPassword(System.console().readPassword("Enter %s: ", pc.getPrompt()));
                } else throw new UnsupportedCallbackException(c, "We can't get input for " + pc.getPrompt());
            } else if (c instanceof TextOutputCallback) {
                System.out.println(((TextOutputCallback) c).getMessage());
            } else {
                throw new UnsupportedCallbackException(c, "Callback not supported");
            }
        }
    }
}
