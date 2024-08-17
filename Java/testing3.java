import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;



public class UsingPkcs11 {
    public static void main(String[] args) {

        final String configString = "yubikeyHSM.cfg";
        final String keyName = "X.509 Certificate for Key Management";
        final String signatureInstance = "SHA256withRSA";
        final String cipherInstance = "RSA/ECB/NoPadding";
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(configString);
        Security.addProvider(p);
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS11");
            keyStore.load(null, args[0].toCharArray());
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, null);
            final Certificate cert = keyStore.getCertificate(keyName);
            System.out.println(privateKey);
            System.out.println(privateKey.getEncoded());
            System.out.println(cert.getPublicKey());
            // encrypt
            Cipher cipher = Cipher.getInstance(cipherInstance);
            cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
            byte[] bytesToEncrypt = "Hello, World!".getBytes();
            byte[] output = cipher.doFinal(bytesToEncrypt);
            System.out.println("Output address: " + output);
            //TODO: convert to base64 and print
            System.out.println("as String '" + (new String(output, Charset.defaultCharset())) + "'");
            System.out.println();

            Cipher decipher = Cipher.getInstance(cipherInstance, p);
            decipher.init(Cipher.DECRYPT_MODE, privateKey); //Missing key encoding
            byte[] output2 = decipher.doFinal(output);
            System.out.println("Output2 address: " + output2);
            //TODO: convert to base64 and print
            System.out.println("as String '" + (new String(output2, Charset.defaultCharset())) + "'");

            // dum dum below, make sure using decipher, not cipher
            //Cipher decipher = Cipher.getInstance(cipherInstance, p);
            //cipher.init(Cipher.DECRYPT_MODE, privateKey); //Missing key encoding
            //byte[] output2 = cipher.doFinal(output);
            //System.out.println(output2);


            // create a signature
            /* 
            cipher.init(0, null);
            byte[] bytesToSign = "Hello, World!".getBytes();
            signature.update(bytesToSign);
            byte[] signed = signature.sign();
            System.out.println(signed);
            */
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
