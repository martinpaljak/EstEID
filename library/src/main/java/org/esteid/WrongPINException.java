package org.esteid;

import apdu4j.ResponseAPDU;

public class WrongPINException extends RuntimeException {
    private static final long serialVersionUID = -258528925655515489L;

    private String status;
    private byte remaining;

    private WrongPINException(byte remaining, String status) {
        this.remaining = remaining;
        this.status = status;
    }

    public static ResponseAPDU check(ResponseAPDU r) throws WrongPINException {
        check(r.getSW());
        return r;
    }

    public static void check(int sw) throws WrongPINException {
        if ((sw & 0x6300) == 0x6300) {
            throw new WrongPINException((byte) (sw & 0xF), "");
        } else if (sw == 0x6983) { // FIXME symbol
            throw new WrongPINException((byte) 0, " (blocked)");
        }
    }

    public byte getRemaining() {
        return remaining;
    }

    @Override
    public String toString() {
        return "Wrong PIN: " + getRemaining() + " tries remaining" + status;
    }
}
