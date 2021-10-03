package com.tylerjette;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

public class Server {
    /**member variables**/
    private Socket socket;
    private ObjectInputStream inStream = null;
    private ObjectOutputStream outStream = null;
    private byte[] clientNonce_received = null; //gets from client
    private Certificate serverCertificate = null;
    private Certificate clientCertificate = null;
    private BigInteger DH_N = null;
    private BigInteger DH_G = null;
    private BigInteger privateDHKey = null; // generated from DH.getPrivateDHKey()
    private BigInteger publicDHKey = null; //calculated from serverG.modPow(privateServerDHKey_BI, serverN);
    private BigInteger DHSharedSecretKey = null; //co-generated with client
    private BigInteger clientPublicDHKey = null;
    private PublicKey clientPublicRSAKey = null;
    private PrivateKey privateRSAKey = null;
    private Cipher RSASignatureCipher = null;
    private Cipher clientRSAValidator = null;
    private ArrayList<Byte> handshake_log = null;

    /**session keys member variables**/
    private SessionKeysSet sessionKeys = null;

    /**constructor**/
    public Server(Socket socket) throws IOException{
        this.socket = socket;
        inStream = new ObjectInputStream(this.socket.getInputStream());
        outStream = new ObjectOutputStream(this.socket.getOutputStream());;
        this.serverCertificate = CertificateGenerator.getServerCertificate();
        /**Server retrieves its RSA private key (previously generated, and available via RSA.getServerPrivateKey())
         * to complete RSA signature **/
        this.privateRSAKey = RSA.getServerPrivateKey();
        try {
            this.RSASignatureCipher = Cipher.getInstance("RSA");
            this.RSASignatureCipher.init(Cipher.ENCRYPT_MODE, this.privateRSAKey);
        }catch(javax.crypto.NoSuchPaddingException | java.security.NoSuchAlgorithmException | java.security.InvalidKeyException e){
            e.printStackTrace();
        }
        this.handshake_log = new ArrayList<>();
        calculate_DH_Key();
    };

    private void calculate_DH_Key(){
        /**Client calculates its own DH private key**/
        this.privateDHKey = DH.getPrivateDHKey();
        this.DH_N = DH.getMod();
        this.DH_G = DH.getBase();

        /**with privateDHKey, N and G, client can calculate its public DH key**/
        this.publicDHKey = DH_G.modPow(this.privateDHKey, DH_N);
    }

    private void send_preMACPACK_handshake_msg(Object msg){
        try{
            this.outStream.writeObject(msg);
            if(msg instanceof BigInteger){
                add_to_log(((BigInteger) msg).toByteArray());
            }else if(msg instanceof Certificate){
                try {
                    add_to_log(((Certificate) msg).getEncoded());
                }catch(java.security.cert.CertificateEncodingException e){
                    e.printStackTrace();
                }
            }else{
                add_to_log((byte[])msg);
            }
        }catch(IOException e){
            e.printStackTrace();
        }
    }
    public byte[] receive_preMACPACK_handshake_msg(){
        byte[] ret = null;
        try{
            ret = (byte[])this.inStream.readObject();
            add_to_log(ret);
        }catch(java.io.IOException | java.lang.ClassNotFoundException e){
            e.printStackTrace();
        }
        return ret;
    }

    public void add_to_log(byte[] bytes){
        for(int i = 0; i < bytes.length; i++){
            this.handshake_log.add(bytes[i]);
        }
    }

    public boolean readCertificate(){
        try{
            this.clientCertificate = (X509Certificate)inStream.readObject();
            add_to_log(this.clientCertificate.getEncoded());

            /**server can then verify the Certificate**/
            if(VerifyCertificate.verify(clientCertificate) == false){
                return false;
            }
            this.clientPublicRSAKey = this.clientCertificate.getPublicKey();
            this.clientRSAValidator = Cipher.getInstance("RSA");
            this.clientRSAValidator.init(Cipher.DECRYPT_MODE, this.clientPublicRSAKey);
        }catch(IOException | java.lang.ClassNotFoundException |
                java.security.cert.CertificateEncodingException  |
                java.security.NoSuchAlgorithmException |
                javax.crypto.NoSuchPaddingException |
                java.security.InvalidKeyException
                e){
            e.printStackTrace();
        }
        return true;
    }

    public boolean abort(){
        try{
            outStream.close();
            inStream.close();
            socket.close();
        }catch(IOException e){
            e.printStackTrace();
        }
        return false;
    }

    public boolean handshake() throws IOException {

        /**message 1(incoming)  from client is client hello, + Client nonce -> gets stored as clientNonce_received  **/
        this.clientNonce_received = receive_preMACPACK_handshake_msg();

        /**message 2 -> to client(Certificate)**/
        send_preMACPACK_handshake_msg(this.serverCertificate);

        /**message 3 -> to client(DHpub)**/
        send_preMACPACK_handshake_msg(this.publicDHKey);

        /**message 4 -> to client(signed[public DH key]**/
        send_preMACPACK_handshake_msg(RSA.sign(RSASignatureCipher, publicDHKey));

        /**massage...oh, that sounds nice...message 5 -> Client then sends its certificate to the server**/
        if(readCertificate() == false){
            return abort();
        }

        /**client then sends its publicDH key**/
        try{
            this.clientPublicDHKey = (BigInteger)inStream.readObject();
        }catch(java.lang.ClassNotFoundException e){
            e.printStackTrace();
        }
        add_to_log(this.clientPublicDHKey.toByteArray());

        /**Client then sends its RSA encoded public DH key**/
        byte[] RSA_encoded_client_DH_Key = null;
        try {
            RSA_encoded_client_DH_Key = (byte[])inStream.readObject();
            add_to_log(RSA_encoded_client_DH_Key);
        }catch(java.lang.ClassNotFoundException e){
            e.printStackTrace();
        }

        if(RSA.validateClient(clientRSAValidator, RSA_encoded_client_DH_Key, clientPublicDHKey) == false){
            return abort();
        }

        /**now that the server has the client's public DH key, it can calc its DH shared secret key**/
        this.DHSharedSecretKey = this.clientPublicDHKey.modPow(this.privateDHKey, this.DH_N);

        /**...can derive session keys...**/
        SessionKeysSet sessionKeys = new SessionKeysSet(DHSharedSecretKey, clientNonce_received);

        /**Server sends the client MAC[all of the messages so far]**/
        byte[] msgDumpMAC = new byte[this.handshake_log.size()];
        for(int i = 0; i < this.handshake_log.size(); i++){
            msgDumpMAC[i] = this.handshake_log.get(i);
        }
        outStream.writeObject(sessionKeys.Server_serverMAC_instance.doFinal(msgDumpMAC));

        /**Client send Server MAC[all messages so far]**/
        byte[] ClientMACKED_received = null;
        try{
            ClientMACKED_received = (byte[])inStream.readObject();
        }catch(java.lang.ClassNotFoundException e){
            e.printStackTrace();
        }

        /***Server Calculates its own version of the MAC dump from the client*/
        byte[] ClientMACKED_Calculated_ServerSide = sessionKeys.Server_clientMAC_instance.doFinal(msgDumpMAC);
        BigInteger c_mac_BI = new BigInteger(ClientMACKED_Calculated_ServerSide);

        BigInteger receivedMsgDumpBI = new BigInteger(ClientMACKED_received);
        if(c_mac_BI.compareTo(receivedMsgDumpBI) != 0){
            return abort();
        }

        /**handshake is done**/

        return true;
    }

    public void fileTransfer(){
        fileTransfer.transfer(outStream, sessionKeys.Server_serverMAC_instance, sessionKeys.sessionEncryptionCipher);
    };

}
