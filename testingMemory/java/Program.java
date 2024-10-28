import java.io.IOException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Program {
    public static void main(String[] args) throws IOException {
        byte[] key = {
            (byte) 189,
            (byte) 60,
            (byte) 110,
            (byte) 254,
            (byte) 134,
            (byte) 100,
            (byte) 130,
            (byte) 85,
            (byte) 46,
            (byte) 177,
            (byte) 138,
            (byte) 224,
            (byte) 223,
            (byte) 222,
            (byte) 158,
            (byte) 250
        };
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        System.in.read();
    }

}
    