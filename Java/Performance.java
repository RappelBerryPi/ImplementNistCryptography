import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;

import javax.crypto.SecretKey;

public class Performance {
    // 9a - RSA 2048
    // 9c - ECC 384
    public static void main(String[] args) {
        final String configString = "YubikeyHSM.cfg";
        //final String keyName = "X.509 Certificate for Digital Signature"; // ECDSA
        // final String signatureInstance = "SHA256withECDSA";
        final String keyName = "X.509 Certificate for PIV Authentication";
        final String signatureInstance = "SHA256withRSA";
        Provider p = Security.getProvider("SunPKCS11");
        p = p.configure(configString);
        Security.addProvider(p);
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS11", p);
            keyStore.load(null, args[0].toCharArray());
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, null);
            Signature signature = Signature.getInstance(signatureInstance, p);

            // encrypt
            byte[] data = "abc".getBytes();

            Instant start = Instant.now();
            for (int i = 0; i < 100; i++) {
                signature.initSign(privateKey);
                signature.update(data);
                signature.sign();
            }
            Instant finish = Instant.now();
            Duration duration = Duration.between(start, finish);
            System.out.println(duration.toMillis());

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
