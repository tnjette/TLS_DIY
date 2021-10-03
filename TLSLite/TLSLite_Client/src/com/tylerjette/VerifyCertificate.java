package com.tylerjette;

import java.security.cert.Certificate;

public class VerifyCertificate {
    public VerifyCertificate(){};
    public static boolean verify(Certificate toVerify){

        /**read in CAcertificate.pem**/
        Certificate CAcertificate = CertificateGenerator.getCACertificate();
        try{
            toVerify.verify(CAcertificate.getPublicKey());
        }catch(java.security.cert.CertificateException
                | java.security.NoSuchAlgorithmException
                | java.security.InvalidKeyException
                | java.security.NoSuchProviderException
                | java.security.SignatureException e){
            e.printStackTrace();
            return false;
        }

        return true; //for now
    }
}
