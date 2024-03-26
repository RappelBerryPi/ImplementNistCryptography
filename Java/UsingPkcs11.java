import java.io.IOException;
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
import java.security.cert.CertificateException;



public class UsingPkcs11 {
    public static void main(String[] args) {
        final String configString = "softHSM.cfg";
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(configString);
        Security.addProvider(p);
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS11");
            keyStore.load(null, args[0].toCharArray());
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey("RSAKEY1", null);
            System.out.println(privateKey);
            System.out.println(privateKey.getEncoded());

            // create a signature
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            byte[] bytesToSign = "Hello, World!".getBytes();
            signature.update(bytesToSign);
            byte[] signed = signature.sign();
            System.out.println(signed);
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
        } catch (SignatureException e) {
            e.printStackTrace();
        }

    }
}
