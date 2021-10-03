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

    public static Certificate getClientCertificate(){
        CertificateGenerator certificateGenerator = new CertificateGenerator();
        InputStream certificateInputStream = null;
        try{
            certificateInputStream = new FileInputStream(<your .pem file>);

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

    public static Certificate getCACertificate(){
        //CertificateGenerator certificateGenerator = new CertificateGenerator();
        InputStream certificateInputStream = null;
        try{
            certificateInputStream = new FileInputStream(<your .pem file>);

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
