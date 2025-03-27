import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class RSAYubikeyAESKeyUnwrapAndUse {
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


            //set the AES key bytes by decrypting it
            String EncryptedAESKeyString = new String(Files.readAllBytes(Paths.get("EncryptedAESKey.txt")));
            byte[] EncryptedAESKey = Base64.getDecoder().decode(EncryptedAESKeyString);
            Cipher decryptCipher = Cipher.getInstance(cipherInstance);
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedAESKey = decryptCipher.doFinal(EncryptedAESKey);
            byte[] AESKey = new byte[32];
            for (int i = 224; i < 256; i++) {
                AESKey[i - 224] = decryptedAESKey[i];
            }

            // pull in the encrypted string and the IV
            String EncryptedValue = new String(Files.readAllBytes(Paths.get("EncryptedCipherText.txt")));
            String IVString = EncryptedValue.substring(0,24);
            String CipherTextString = EncryptedValue.substring(24);
            byte[] IV = Base64.getDecoder().decode(IVString);
            byte[] cipherText = Base64.getDecoder().decode(CipherTextString);

            //call the AES decryption function
            Cipher AESDecryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(AESKey, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(IV);
            AESDecryptor.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            byte[] plaintextBytes = AESDecryptor.doFinal(cipherText);
            String plaintext = new String(plaintextBytes);
            System.out.println(plaintext);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
