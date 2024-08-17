import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.SecureRandom;
import java.util.Set;



public class UsingPkcs11 {
    public static void main(String[] args) {
        try {
            final String configString = "yubikeyHSM.cfg";
            //final String keyName = "X.509 Certificate for Digital Signature";
            //final String signatureInstance = "SHA256withECDSA";
            Provider p = Security.getProvider("SunPKCS11");
            p = p.configure(configString);
            Security.addProvider(p);
            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(new BigInteger("10"), new BigInteger("10"));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", p);
            PrivateKey privatekey = keyFactory.generatePrivate(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
