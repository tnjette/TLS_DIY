package com.tylerjette;

import java.io.IOException;

public class Main {

    public static void main(String[] args) throws IOException {
         Client client = new Client();
         if(client.handshake()){
             client.fileTransfer();
         }else{
             System.out.println("Error completing handshake");
         }
    }

}
