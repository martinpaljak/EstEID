package org.esteid.jca;

// TODO: use javax.security.auth.callback.CallbackHandler instead ?
public interface NotificationInterface {
    void showControlCode(String code);
    String askPinCode(String info);
}
