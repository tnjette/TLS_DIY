package com.tylerjette;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Main {

    private static final int PORT = 8080;
    private SecretKey clientKey = null;

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Listening on port " + PORT);
        Socket socket = null;

        while(true){
            socket = serverSocket.accept(); //blocks until true
            System.out.println("socket accepted");
            Server server = new Server(socket);
            if(server.handshake()){
                server.fileTransfer();
            }else{
                System.out.println("Error completing handshake");
            }
        }
    }

}
