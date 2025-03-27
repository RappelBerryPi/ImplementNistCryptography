import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.nio.file.Path;
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



public class RSAYubikeyAESKeyWrap {
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

            byte[] bytes = new byte[32]; 
            byte[] iv = new byte[16];

            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(bytes);
            secureRandom.nextBytes(iv);

            // keyWrap 
            Cipher encryptCipher = Cipher.getInstance(cipherInstance);
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedKey = encryptCipher.doFinal(bytes);

            // create AES cipher from plaintext key
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(bytes, "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

            //encrypt the string "abc" and save it to the file with the IV
            byte[] cipherText = aesCipher.doFinal("abc".getBytes());
            File file = new File("EncryptedCipherText.txt");
            file.createNewFile();
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            OutputStreamWriter sw = new OutputStreamWriter(fileOutputStream);
            //write the IV
            sw.write(Base64.getEncoder().encodeToString(iv));
            //write the cipherText
            sw.write(Base64.getEncoder().encodeToString(cipherText));
            sw.close();
            fileOutputStream.close();
            
            // clear the key once done with it
            for (int i = 0; i < 32; i++) {
                bytes[i] = 0x00;
            }
            secretKey = null;
            aesCipher = null;

            // write the encrypted AES key to a file
            String encryptedKeyString = Base64.getEncoder().encodeToString(encryptedKey);
            file = new File("EncryptedAESKey.txt");
            file.createNewFile();
            fileOutputStream = new FileOutputStream(file);
            sw = new OutputStreamWriter(fileOutputStream);
            sw.write(encryptedKeyString);
            sw.close();
            fileOutputStream.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
