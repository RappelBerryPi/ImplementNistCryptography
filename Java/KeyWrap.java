import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;



public class KeyWrap {
    public static void main(String[] args) {
        final String configString = "softHSM.cfg";
        final String keyName = "AESKEY1";
        // final String signatureInstance = "SHA256withRSA";
        final String cipherInstance = "AES/ECB/NoPadding";

        //final String configString = "yubikeyHSM.cfg";
        //final String keyName = "X.509 Certificate for Digital Signature";
        //final String signatureInstance = "SHA256withECDSA";
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(configString);
        Security.addProvider(p);
        p.getServices().stream().forEach(s -> {
            System.out.println(s.getAlgorithm());
        });
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS11", p);
            keyStore.load(null, args[0].toCharArray());
            final SecretKey wrappingKey = (SecretKey) keyStore.getKey(keyName, null);
            final SecretKey keyToWrap = (SecretKey) keyStore.getKey("AESKEY2", null);

            System.out.println(wrappingKey);
            System.out.println(wrappingKey.getEncoded());

            System.out.println(keyToWrap);
            System.out.println(keyToWrap.getEncoded());

            // create a signature
            Cipher cipher = Cipher.getInstance(cipherInstance, p);
            cipher.init(Cipher.WRAP_MODE, wrappingKey);
            byte[] wrappedKey = cipher.wrap(keyToWrap);
            System.out.println(wrappedKey);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

    }
}
