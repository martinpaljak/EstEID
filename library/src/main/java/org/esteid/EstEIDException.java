package org.esteid;

import apdu4j.ResponseAPDU;

import java.util.Arrays;
import java.util.stream.Collectors;

// Exceptions
public class EstEIDException extends RuntimeException {
    private static final long serialVersionUID = 475857378850855495L;

    public EstEIDException(String msg) {
        super(msg);
    }

    public EstEIDException(String msg, Throwable reason) {
        super(msg, reason);
    }

    public static ResponseAPDU check(ResponseAPDU r) throws EstEIDException {
        return check(r, "Unexpected response", 0x9000);
    }

    public static ResponseAPDU check(ResponseAPDU r, String message) throws EstEIDException {
        return check(r, message, 0x9000);
    }

    static String SW(int sw) {
        return String.format("%04X", sw).toUpperCase();
    }

    public static ResponseAPDU check(ResponseAPDU response, String message, Integer... sws) throws EstEIDException {
        for (int sw : sws) {
            if (response.getSW() == sw) {
                return response;
            }
        }
        // Fallback
        if (response.getSW() == 0x9000) {
            return response;
        }
        throw new EstEIDException(message + ". Received " + SW(response.getSW()) + ", expected " + String.join(", ", Arrays.stream(sws).map(sw -> SW(sw)).collect(Collectors.toList())));
    }
}
