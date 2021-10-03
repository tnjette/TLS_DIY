package com.tylerjette;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SessionKeysSet {
    /**these member variables consist of the set of DH-derived keys**/
        private byte[] ClientDHSharedSecret_asbyteArray;

        private byte[] Client_prk;
        public byte[] Client_serverEncrypt;
        public byte[] Client_clientEncrypt;
        public byte[] Client_serverMAC;
        public byte[] Client_clientMAC;
        public byte[] Client_serverIV;
        public byte[] Client_clientIV;

        public SecretKeySpec Client_serverEncrypt_Key;
        public SecretKeySpec Client_clientEncrypt_Key;
        public SecretKeySpec Client_serverMAC_key;
        public SecretKeySpec Client_clientMAC_key;

        public static Mac Client_serverMAC_instance;
        public static Mac Client_clientMAC_instance;

        public static IvParameterSpec Client_serverIV_key;
        public static IvParameterSpec Client_clientIV_key;

        public static Cipher sessionDecryptionCipher; //-> used for decrypting messages from Server
        public static Cipher sessionEncryptionCipher; //-> used for encrypting messages to Server

    public SessionKeysSet(BigInteger DHSharedSecretKey, byte[] publicClientNonce){
        ClientDHSharedSecret_asbyteArray = DHSharedSecretKey.toByteArray();

        //raw byte arrays
        Client_prk = HMAC.HMAC(publicClientNonce, ClientDHSharedSecret_asbyteArray);
        Client_serverEncrypt = HMAC.hkdfExpand(Client_prk, "server encrypt");
        Client_clientEncrypt = HMAC.hkdfExpand(Client_serverEncrypt, "client encrypt");
        Client_serverMAC = HMAC.hkdfExpand(Client_clientEncrypt, "server MAC");
        Client_clientMAC = HMAC.hkdfExpand(Client_serverMAC, "client MAC");
        Client_serverIV = HMAC.hkdfExpand(Client_clientMAC, "server IV");
        Client_clientIV = HMAC.hkdfExpand(Client_serverIV, "client IV");

        //convert to java secret key classes
        Client_serverEncrypt_Key = new SecretKeySpec(Client_serverEncrypt, "AES");
        Client_clientEncrypt_Key = new SecretKeySpec(Client_clientEncrypt, "AES");
        Client_serverMAC_key = new SecretKeySpec(Client_serverMAC, "AES");
        Client_clientMAC_key = new SecretKeySpec(Client_clientMAC, "AES");

        Client_serverMAC_instance = null;
        Client_clientMAC_instance = null;
        try{
            Client_serverMAC_instance = Mac.getInstance("HmacSHA256");
            Client_serverMAC_instance.init(Client_serverMAC_key); //Now you can start calculating MAC values with this

            Client_clientMAC_instance = Mac.getInstance("HmacSHA256");
            Client_clientMAC_instance.init(Client_clientMAC_key);
        }catch(NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch(InvalidKeyException e){
            e.printStackTrace();
        }

        Client_serverIV_key = new IvParameterSpec(Client_serverIV);
        Client_clientIV_key = new IvParameterSpec(Client_clientIV);

        /**Client can then instantiate an encryption and decryptioncipher for this session**/
        try{
            sessionDecryptionCipher = Cipher.getInstance("AES/CBC/NoPadding");
            sessionDecryptionCipher.init(Cipher.DECRYPT_MODE, Client_serverEncrypt_Key, Client_serverIV_key);

            sessionEncryptionCipher = Cipher.getInstance("AES/CBC/NoPadding");
            sessionEncryptionCipher.init(Cipher.ENCRYPT_MODE, Client_clientEncrypt_Key, Client_clientIV_key);

        }catch(java.security.NoSuchAlgorithmException | javax.crypto.NoSuchPaddingException |
                java.security.InvalidKeyException | java.security.InvalidAlgorithmParameterException e){
            e.printStackTrace();
        }/**this then gets sent to the fileTransfer class to be used to send the subsequent messages**/

    }
}
