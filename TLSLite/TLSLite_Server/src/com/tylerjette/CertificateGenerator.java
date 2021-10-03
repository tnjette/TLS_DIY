package com.tylerjette;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class CertificateGenerator {
    private static CertificateFactory certificateFactory = null;

    public CertificateGenerator(){
        try{
            this.certificateFactory = CertificateFactory.getInstance("X.509");
        }catch(java.security.cert.CertificateException e){
            e.printStackTrace();
        }
    };
    public static Certificate getServerCertificate(){
        CertificateFactory certificateFactory = null;
        try{
            certificateFactory = CertificateFactory.getInstance("X.509");
        }catch(java.security.cert.CertificateException e){
            e.printStackTrace();
        }        CertificateGenerator gen = new CertificateGenerator();

        InputStream certificateInputStream = null;
        Certificate certificate = null; //Todo: see if this can be a regular certificate object now...

        try{
            certificateInputStream = new FileInputStream(<path-to-Certificate-authority-signed-ServerCertificate-pem>);
            certificate =  certificateFactory.generateCertificate(certificateInputStream);

        }catch(IOException e){
            e.printStackTrace();
        }catch(java.security.cert.CertificateException e){
            e.printStackTrace();
        }

        return certificate;
    }

    public static Certificate getCACertificate(){

        InputStream certificateInputStream = null;
        try{
            certificateInputStream = new FileInputStream(<path-to-Certificate-authority-Certificate-pem>);

        }catch(IOException e){
            e.printStackTrace();
        }
        Certificate certificate = null;
        try {
            certificate = certificateFactory.generateCertificate(certificateInputStream);
        }catch(java.security.cert.CertificateException e){
            e.printStackTrace();
        }
        return certificate;
    }
}


