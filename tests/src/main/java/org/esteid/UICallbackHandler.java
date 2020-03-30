package org.esteid;

import javax.security.auth.callback.*;
import javax.swing.*;
import java.awt.*;

public class UICallbackHandler extends JPanel implements CallbackHandler {

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        for (Callback c : callbacks) {
            if (c instanceof PasswordCallback) {
                PasswordCallback pc = (PasswordCallback) c;
                if (System.getenv().containsKey(pc.getPrompt())) {
                    pc.setPassword(System.getenv(pc.getPrompt()).toCharArray());
                } else if (System.console() != null) {
                    pc.setPassword(System.console().readPassword("Enter %s: ", pc.getPrompt()));
                } else if (!GraphicsEnvironment.isHeadless()) {
                    JFrame jf=new JFrame();
                    jf.setAlwaysOnTop(true);

                    JPasswordField pf = new JPasswordField();
                    pf.requestFocusInWindow();
                    int okCxl = JOptionPane.showConfirmDialog(jf, pf, pc.getPrompt(), JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

                    if (okCxl == JOptionPane.OK_OPTION) {
                        String password = new String(pf.getPassword());
                        System.err.println("You entered: " + password);
                       // System.out.println("Password is " + pwd);
                        pc.setPassword(pf.getPassword());
                    } else {
                        pc.setPassword(null);
                    }
                    //int response = JOptionPane.showConfirmDialog(jf,"Message", "Title", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
                    //String pwd = JOptionPane.showInputDialog(jf, String.format("Enter %s", pc.getPrompt()));

                } else throw new UnsupportedCallbackException(c, "We can't get input for " + pc.getPrompt());
            } else if (c instanceof TextOutputCallback) {
                System.out.println(((TextOutputCallback) c).getMessage());
            } else {
                throw new UnsupportedCallbackException(c, "Callback not supported");
            }
        }
    }
}
