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
import java.security.SecureRandom;
import java.util.Set;



public class UsingPkcs11 {
    public static void main(String[] args) {
        // final String configString = "softHSM.cfg";
        // final String keyName = "RSAKEY1";
        // final String signatureInstance = "SHA256withRSA";

        final String configString = "yubikeyHSM.cfg";
        final String keyName = "X.509 Certificate for Digital Signature";
        final String signatureInstance = "SHA256withECDSA";
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(configString);
        Security.addProvider(p);
        Set<Provider.Service> services = p.getServices();
        services.forEach(service -> {
                System.out.println(service.getType() + "\t" + service.getAlgorithm()); // --> Look for 'SecureRandom' type
        });
        /*
        try {
            SecureRandom random = SecureRandom.getInstance("PKCS11", p);
            byte bytes[] = new byte[20];
            random.nextBytes(bytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        */

    }
}
