import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;



public class UsingPkcs11v2 {
    public static void main(String[] args) {
        // final String configString = "softHSM.cfg";
        // final String keyName = "RSAKEY1";
        // final String cipherInstance = "SHA256withRSA";

        final String configString = "yubikeyHSM.cfg";

        //final String publicKeyName = "Public key for Key Management";
        final String publicKeyName = "X.509 Certificate for Key Management";


        final String cipherInstance = "RSA/ECB/NoPadding";
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(configString);
        Security.addProvider(p);
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS11");
            keyStore.load(null, args[0].toCharArray());
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(publicKeyName, null);
            final PublicKey publicKey = (PublicKey) keyStore.getCertificate(publicKeyName).getPublicKey();
            System.out.println(privateKey);
            System.out.println(publicKey);

            byte[] bytes = "abc".getBytes();

            // create a signature
            Cipher encryptCipher = Cipher.getInstance(cipherInstance);
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] newBytes = encryptCipher.doFinal(bytes);

            Cipher decryptCipher = Cipher.getInstance(cipherInstance);
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] oldBytes = decryptCipher.doFinal(newBytes);
            String original = new String(bytes);
            String newOriginal = new String(oldBytes);
            String cipherText = new String(newBytes);
            System.out.println(original);
            System.out.println(newOriginal);
            System.out.println(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
