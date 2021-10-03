package com.tylerjette;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SessionKeysSet {

    public byte[] ServerDHSharedSecret_asbyteArray;

    public byte[] Server_prk;
    public byte[] Server_serverEncrypt;
    public byte[] Server_clientEncrypt;
    public byte[] Server_serverMAC;
    public byte[] Server_clientMAC;
    public byte[] Server_serverIV;
    public byte[] Server_clientIV;

    public SecretKeySpec Server_serverEncrypt_Key;
    public SecretKeySpec Server_clientEncrypt_Key;
    public SecretKeySpec Server_serverMAC_key;
    public SecretKeySpec Server_clientMAC_key;

    public static Mac Server_serverMAC_instance;
    public static Mac Server_clientMAC_instance;

    public static IvParameterSpec Server_serverIV_key;
    public static IvParameterSpec Server_clientIV_key;

    public static Cipher sessionEncryptionCipher;
    public static Cipher sessionDecryptionCipher;

    public SessionKeysSet(BigInteger DHSharedSecretKey, byte[] clientNonce_received){
        /**server derives 6 session keys from this.DHSharedSecretKey**/

        ServerDHSharedSecret_asbyteArray = DHSharedSecretKey.toByteArray();

        Server_prk = HMAC.HMAC(clientNonce_received, ServerDHSharedSecret_asbyteArray);
        Server_serverEncrypt = HMAC.hkdfExpand(Server_prk, "server encrypt");
        Server_clientEncrypt = HMAC.hkdfExpand(Server_serverEncrypt, "client encrypt");
        Server_serverMAC = HMAC.hkdfExpand(Server_clientEncrypt, "server MAC");
        Server_clientMAC = HMAC.hkdfExpand(Server_serverMAC, "client MAC");
        Server_serverIV = HMAC.hkdfExpand(Server_clientMAC, "server IV");
        Server_clientIV = HMAC.hkdfExpand(Server_serverIV, "client IV");

        //convert to java secret key classes
        Server_serverEncrypt_Key = new SecretKeySpec(Server_serverEncrypt, "AES"); // = Server_serverEncrypt
        Server_clientEncrypt_Key = new SecretKeySpec(Server_clientEncrypt, "AES"); // = Server_clientEncrypt
        Server_serverMAC_key = new SecretKeySpec(Server_serverMAC, "AES");
        Server_clientMAC_key = new SecretKeySpec(Server_clientMAC, "AES");

        Server_serverMAC_instance = null;
        Server_clientMAC_instance = null;
        try{
            Server_serverMAC_instance = Mac.getInstance("HmacSHA256");
            Server_serverMAC_instance.init(Server_serverMAC_key); //Now you can start calculating MAC values with this

            Server_clientMAC_instance = Mac.getInstance("HmacSHA256"); //this is for comparing to validate the hashed msg from client
            Server_clientMAC_instance.init(Server_clientMAC_key);
        }catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch(InvalidKeyException e){
            e.printStackTrace();
        }
        Server_serverIV_key = new IvParameterSpec(Server_serverIV);
        Server_clientIV_key = new IvParameterSpec(Server_clientIV);

        /**Server can then instantiate an(encryption) cipher for this session**/
        try{
            sessionEncryptionCipher = Cipher.getInstance("AES/CBC/NoPadding");
            sessionEncryptionCipher.init(Cipher.ENCRYPT_MODE, Server_serverEncrypt_Key, Server_serverIV_key);

            sessionDecryptionCipher = Cipher.getInstance("AES/CBC/NoPadding");
            sessionDecryptionCipher.init(Cipher.DECRYPT_MODE, Server_clientEncrypt_Key, Server_clientIV_key);
        }catch(java.security.NoSuchAlgorithmException | javax.crypto.NoSuchPaddingException |
                java.security.InvalidKeyException | java.security.InvalidAlgorithmParameterException e){
            e.printStackTrace();
        }/**this then gets sent to the fileTransfer class to be used to send the subsequent messages**/

    }
}
