package com.tylerjette;

import javax.crypto.Cipher;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class RSA {
    public RSA(){};

    public static PrivateKey getClientsPrivateKey(){
        RSA rsa = new RSA();
        byte[] keyBytes = null;
        try{
            keyBytes = Files.readAllBytes(Paths.get(<path-to-client-.der-file>));
        }catch(IOException e){
            e.printStackTrace();
        }
        //return new SecretKeySpec(keyBytes, "AES");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

        PrivateKey ret = null;
        try{
            KeyFactory kf = KeyFactory.getInstance("RSA");
            ret = kf.generatePrivate(spec);
        }catch(java.security.spec.InvalidKeySpecException e){
            e.printStackTrace();
        }catch(java.security.NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        return ret;
    }

    public static boolean verify(Cipher serverValidationCipher, byte[] serverPublicDHKey_Signed, BigInteger serverPublicDHKey){
        BigInteger serverDHCipherValidate = null;
        try{
            serverDHCipherValidate = new BigInteger(serverValidationCipher.doFinal(serverPublicDHKey_Signed));
        }catch( javax.crypto.IllegalBlockSizeException | javax.crypto.BadPaddingException e){
            e.printStackTrace();
        }

        /**compare the plain server public DH key with the server's (RSA public key-encrypted) public DH key**/
        if(serverPublicDHKey.compareTo(serverDHCipherValidate) != 0){
            return false;
        }
        return true;
    }

    public static byte[] sign(Cipher RSASignatureCipher, BigInteger publicDHKey){
        byte[] publicDHKey_Encrypted_withRSAKey = null;
        try{
            publicDHKey_Encrypted_withRSAKey = RSASignatureCipher.doFinal(publicDHKey.toByteArray());
        }catch(javax.crypto.IllegalBlockSizeException | javax.crypto.BadPaddingException e){
            e.printStackTrace();
        }
        return publicDHKey_Encrypted_withRSAKey;
    }
}

