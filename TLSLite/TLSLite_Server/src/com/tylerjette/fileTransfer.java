package com.tylerjette;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class fileTransfer implements Serializable{

    private ObjectOutputStream outStream = null;
    private Mac sessionServerMacKey = null;
    private Cipher sessionEncryptionCipher = null;

    public fileTransfer(ObjectOutputStream out, Mac mac, Cipher cipher){
        this.outStream = out;
        this.sessionServerMacKey = mac;
        this.sessionEncryptionCipher = cipher;
    }

    public static void transfer(ObjectOutputStream outStream, Mac sessionServerMacKey, Cipher sessionServerCipher ){
        System.out.println("transferring file...");
        fileTransfer ft = new fileTransfer(outStream, sessionServerMacKey, sessionServerCipher);

        Path file = Paths.get("../file_to_send.pdf");
        byte[] fileBytes = null;
        try{
            fileBytes = Files.readAllBytes(file);
        }catch(IOException e){
            e.printStackTrace();
        }
        int blockSize = 128;
        int nBlocks = fileBytes.length / blockSize;

        for(int i = 0; i < nBlocks; i++){
            byte[] blockBytes = new byte[blockSize];
            for(int j = 0; j < blockSize; j++){
                blockBytes[j] = fileBytes[(i * blockSize) + j];
            }
            byte[] blockBytes_HMAC = sessionServerMacKey.doFinal(blockBytes);
            /**concat the two, into the TLS Record format, with the first 5 bytes being included for other format fields**/
            byte[] TLSrecord = new byte[(blockBytes.length + blockBytes_HMAC.length)];

            for(int j = 0; j < blockBytes.length; j++){
                TLSrecord[j] = blockBytes[j];
            }
            for(int j = 0; j < blockBytes_HMAC.length; j++){
                TLSrecord[blockBytes.length + j] = blockBytes_HMAC[j];
            }

            byte[] ciphered = sessionServerCipher.update(TLSrecord);
            try{
                outStream.writeObject(ciphered);
            }catch(IOException e){
                e.printStackTrace();
            }
        }
        try{
            outStream.writeObject(null);
        }catch(IOException e){
            e.printStackTrace();
        }
    }
}
