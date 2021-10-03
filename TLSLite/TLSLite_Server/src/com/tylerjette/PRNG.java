package com.tylerjette;

import java.security.SecureRandom;

public class PRNG {

    public PRNG(){};

    public static byte[] getNonce(){
        SecureRandom secureRandom = new SecureRandom();
        byte randomBytes[] = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }

}
