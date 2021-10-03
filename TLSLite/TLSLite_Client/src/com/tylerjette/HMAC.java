package com.tylerjette;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class HMAC {
    public HMAC(){};

    public static byte[] HMAC(byte[] key, byte[] sharedDHKey) {
        byte ret[] = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            ret = mac.doFinal(sharedDHKey);
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        } catch(InvalidKeyException e) {
            e.printStackTrace();
        }
        return ret;
    }

    public static byte[] hkdfExpand(byte[] input, String tag){//tag is a string, but probably convenient to take its contents as byte[]
        byte[] data = new byte[(tag.length() + 1)];
        for(int i = 0; i < tag.length(); i++){
            data[i] = (byte)(tag.charAt(i));
        }

        data[tag.length()] = 1;

        byte[] okm = HMAC(input, data);
        byte[] ret = new byte[16];
        for(int i = 0; i < ret.length; i++){
            ret[i] = okm[i];
        }
        return ret;
    }
}