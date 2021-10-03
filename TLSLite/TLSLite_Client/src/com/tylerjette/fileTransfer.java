package com.tylerjette;

import org.junit.Assert;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.io.*;
import java.math.BigInteger;

public class fileTransfer implements Serializable {

    private ObjectInputStream inStream = null;
    private Mac sessionServerMacKey = null;
    private Cipher sessionServerDecryptionCipher = null;

    public fileTransfer(ObjectInputStream in, Mac mac, Cipher cipher ) {
        this.inStream = in;
        this.sessionServerMacKey = mac;
        this.sessionServerDecryptionCipher = cipher;
    };

    public static void receive(ObjectInputStream in, Mac sessionServerMacKey, Cipher sessionServerCipher){
        fileTransfer ft = new fileTransfer(in, sessionServerMacKey, sessionServerCipher);
        File file = new File("../received.pdf");
        FileOutputStream fileWriter = null;
        try{
            fileWriter = new FileOutputStream(file);
        }catch(FileNotFoundException e){
            e.printStackTrace();
        }
        while(true){
            try{
                byte[] received = (byte[])in.readObject();
                if(received != null){
                    byte[] decipheredRecord = sessionServerCipher.update(received);

                    /**strip the MAC off the message**/
                    byte[] msg = new byte[128];;
                    for(int i = 0; i < 128; i++){
                        msg[i] = decipheredRecord[i];
                    }
                    byte[] msgMAC = new byte[decipheredRecord.length - 128];
                    for(int i = 0; i < decipheredRecord.length -128; i++){
                        msgMAC[i] = decipheredRecord[128 + i];
                    }
                    byte[] calculatedMac = sessionServerMacKey.doFinal(msg);
                    BigInteger SBI = new BigInteger(msgMAC);
                    BigInteger CBI = new BigInteger(calculatedMac);
                    Assert.assertTrue(CBI.compareTo(SBI) == 0);

                    fileWriter.write(msg);

                }else{
                    break;
                }

            }catch(java.io.IOException | java.lang.ClassNotFoundException e){
                e.printStackTrace();
            }
        }
    }
}
