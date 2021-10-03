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
    public static PrivateKey getServerPrivateKey(){

        RSA rsa = new RSA();
        byte[] keyBytes = null;
        try{
            keyBytes = Files.readAllBytes(Paths.get(<path-to-server-Private-Key-der>));
        }catch(IOException e){
            e.printStackTrace();
        }
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
    public static byte[] sign(Cipher RSASignatureCipher, BigInteger publicDHKey){
        byte[] publicDHKey_Encrypted_withRSAKey = null;
        try{
            publicDHKey_Encrypted_withRSAKey = RSASignatureCipher.doFinal(publicDHKey.toByteArray());
        }catch(javax.crypto.IllegalBlockSizeException | javax.crypto.BadPaddingException e){
            e.printStackTrace();
        }
        return publicDHKey_Encrypted_withRSAKey;
    }

    public static boolean validateClient(Cipher clientRSAValidator, byte[] RSA_encoded_client_DH_Key, BigInteger clientPublicDHKey){
        BigInteger decoded = null;
        try{
            decoded = new BigInteger(clientRSAValidator.doFinal(RSA_encoded_client_DH_Key));
        }catch(javax.crypto.IllegalBlockSizeException | javax.crypto.BadPaddingException e){
            e.printStackTrace();
        }
        /**compare decoded to the plain DH**/
        if(decoded.compareTo(clientPublicDHKey) != 0){
            return false;
        }

        return true;
    }

}
