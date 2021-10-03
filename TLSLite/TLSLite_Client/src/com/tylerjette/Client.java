package com.tylerjette;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

public class Client {

    /**member variables**/
    private InetAddress host = null;
    private Socket socket = null;
    private ObjectOutputStream outStream = null;
    private ObjectInputStream inStream = null;
    private Certificate clientCertificate = null;
    private Certificate serverCertificate = null;
    private Cipher serverValidationCipher = null;
    private byte[] publicClientNonce = null;
    private BigInteger DH_N = null;
    private BigInteger DH_G = null;
    private BigInteger privateDHKey = null; // generated from DH.getPrivateDHKey()
    private BigInteger publicDHKey = null; //calculated from serverG.modPow(privateClientDHKey_BI,
    private BigInteger serverPublicDHKey = null; // from server
    private BigInteger DHSharedSecretKey = null; //co-generated with server
    private PublicKey serverPublicRSAKey = null;
    private PrivateKey privateRSAKey = null;
    private Cipher RSASignatureCipher = null;
    private ArrayList<Byte> handshake_log = null;
    private byte[] serverPublicDHKey_Signed = null;

    /**session keys member variables**/
    private SessionKeysSet sessionKeys = null;

    /**constructor**/
    public Client() throws IOException {
        this.host = InetAddress.getLocalHost();
        this.socket = new Socket(host.getHostName(), 8080);
        this.outStream = new ObjectOutputStream(socket.getOutputStream());
        this.inStream = new ObjectInputStream(socket.getInputStream());
        this.clientCertificate = CertificateGenerator.getClientCertificate();
        this.publicClientNonce = PRNG.getNonce();

        /**Client retrieves its RSA private key (previously generated, and available via RSA.getServerPrivateKey())
         * to complete RSA signature **/
        this.privateRSAKey = RSA.getClientsPrivateKey();
        try {
            this.RSASignatureCipher = Cipher.getInstance("RSA");
            this.RSASignatureCipher.init(Cipher.ENCRYPT_MODE, this.privateRSAKey);
        }catch(javax.crypto.NoSuchPaddingException | java.security.NoSuchAlgorithmException | java.security.InvalidKeyException e){
            e.printStackTrace();
        }
        this.handshake_log = new ArrayList<>();
        calculate_DH_Key();
    }

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
                try{
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

    public byte[] receive_handshake_msg(){
        byte[] ret = null;
        try{
            ret = (byte[])this.inStream.readObject();
        }catch(java.io.IOException | java.lang.ClassNotFoundException e){
            e.printStackTrace();
        }
        return ret;
    }

    public boolean readCertificate(){
        try{
            /**reads in the server's Certificate and validates. Returns and closes Streams and ports if validation fails**/
            this.serverCertificate = (X509Certificate) inStream.readObject();
            add_to_log(serverCertificate.getEncoded());
            if(VerifyCertificate.verify(this.serverCertificate) == false){
                return false;
            }
        }catch(java.io.IOException | java.lang.ClassNotFoundException | java.security.cert.CertificateEncodingException e){
            e.printStackTrace();
        }

        /**set servers public RSA Key member variable**/
        this.serverPublicRSAKey = this.serverCertificate.getPublicKey();

        /**initializes the RSA Cipher with the Server's public RSA key**/
        try{
            this.serverValidationCipher = Cipher.getInstance(("RSA"));
            this.serverValidationCipher.init(Cipher.DECRYPT_MODE, this.serverPublicRSAKey);
        }catch(java.security.NoSuchAlgorithmException | javax.crypto.NoSuchPaddingException | java.security.InvalidKeyException e){
            e.printStackTrace();
        }
        return true;
    }

    public void add_to_log(byte[] bytes){
        for(int i = 0; i < bytes.length; i++){
            this.handshake_log.add(bytes[i]);
        }
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

    public boolean handshake() throws IOException{

        /**message 1 -> client sends nonce (public Client Nonce)**/
        send_preMACPACK_handshake_msg(this.publicClientNonce);

        /**message 2 -> receive the Server's Certificate**/
        if(readCertificate() == false){
            return abort();
        };

        /**messages 3,4 -> receive the server's DH public key, and signed DH public key**/
        try{
            this.serverPublicDHKey = (BigInteger)inStream.readObject();
            add_to_log(this.serverPublicDHKey.toByteArray());
            serverPublicDHKey_Signed = (byte[])inStream.readObject();
            add_to_log(serverPublicDHKey_Signed);
        }catch(java.lang.ClassNotFoundException e){
            e.printStackTrace();
        }

        /**client can now verify the DH key is from the Server, with the server's public RSA key**/
        if(RSA.verify(serverValidationCipher, serverPublicDHKey_Signed, serverPublicDHKey) == false){
            return abort();
        }

        /**calculate the shared DH secret key**/
        this.DHSharedSecretKey = this.serverPublicDHKey.modPow(this.privateDHKey, this.DH_N);

        /**message 5 -> then Client can send its Certificate to the server, along with public DH key, and signed DH Key**/
        send_preMACPACK_handshake_msg(clientCertificate);

        /**message 6 -> Client can then send its publicDHKey to the server**/
        send_preMACPACK_handshake_msg(publicDHKey);

        /**message 7 -> Client can then encode its publicDH Key with its
         * public RSA key to send to the Server**/
        send_preMACPACK_handshake_msg(RSA.sign(RSASignatureCipher, publicDHKey));

        /**Client derives 6 session keys from ClientDHSharedSecret key**/
        SessionKeysSet sessionKeys = new SessionKeysSet(this.DHSharedSecretKey, this.publicClientNonce);

        /**message 8 -> Client receives the MAC-ed message dump of the handshake**/
        byte[] ServerMACKED_received = null;
        try{
            ServerMACKED_received = (byte[])inStream.readObject();
        }catch(java.lang.ClassNotFoundException e){
            e.printStackTrace();
        }

        /**Client Calculates its own version of the MAC dump from Server**/
        byte[] msgDumpMAC = new byte[this.handshake_log.size()];
        for(int i = 0; i < this.handshake_log.size(); i++){
            msgDumpMAC[i] = this.handshake_log.get(i);
        }

        byte[] ServerMACKED_Calculated_ClientSide = sessionKeys.Client_serverMAC_instance.doFinal(msgDumpMAC);
        BigInteger s_mac_BI = new BigInteger(ServerMACKED_Calculated_ClientSide);

        BigInteger receivedMsgDumpBI = new BigInteger(ServerMACKED_received);
        if(s_mac_BI.compareTo(receivedMsgDumpBI) != 0){
            return abort();
        }

        /**Client composes its own version of the message dump, and MACs it to send the server**/
        outStream.writeObject(sessionKeys.Client_clientMAC_instance.doFinal(msgDumpMAC));

        /**handshake is done**/

        return true;
    };

    public void fileTransfer(){
        fileTransfer.receive(inStream, sessionKeys.Client_serverMAC_instance, sessionKeys.sessionDecryptionCipher);
    };

}
