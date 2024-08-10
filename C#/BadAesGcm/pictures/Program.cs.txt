using System.Security.Cryptography;
using System.Text;

public class Program {
    public static void Main(string[] args) {
        // set up a static key and IV
        byte[] key = [0, 135, 254, 198, 30, 108, 226, 161, 73, 220, 238, 217, 36, 5, 157, 6, 246, 155, 176, 22, 105, 6, 26, 48, 170, 152, 154, 212, 15, 117, 117, 44];
        byte[] IV = [24, 194, 177, 21, 119, 186, 254, 194, 81, 139, 65, 177];

        // text 1 is what Bob knows
        // text 2 is what Alice knows
        
        string BobPlaintext = "abcdefghijlmnopq";
        string AlicePlaintext = "yes, she is cool";

        // setup the parameters
        byte[] BobPlaintextBytes = Encoding.UTF8.GetBytes(BobPlaintext);
        byte[] AlicePlaintextBytes = Encoding.UTF8.GetBytes(AlicePlaintext);

        byte[] BobCiphertextBytes = new byte[16];
        byte[] AliceCiphertextBytes = new byte[16];

        byte[] BobTag = new byte[16];
        byte[] AliceTag = new byte[16];

        // create one Aes Encryption function with the same key
        AesGcm aesGcm = new AesGcm(key, 16);
        aesGcm.Encrypt(IV, BobPlaintextBytes, BobCiphertextBytes, BobTag);

        aesGcm.Encrypt(IV, AlicePlaintextBytes, AliceCiphertextBytes, AliceTag);

        // I'm now Bob, and I'm going to figure out the XOR bytes for Alice's ciphertext,
        // which is just my ciphertext XORed with my plaintext

        byte[] XorString = new byte[16];

        for (int i = 0; i < 16; i++) {
            XorString[i] = (byte)(BobPlaintextBytes[i] ^ BobCiphertextBytes[i]);
        }

        // now that I have my XorString I'm going to Xor this with Alice's Ciphertext
        // to get back her plaintext without her knowing

        byte[] BobFindsOutAlicesPlaintext = new byte[16];
        for (int i = 0; i < 16; i++) {
            BobFindsOutAlicesPlaintext[i] = (byte)(AliceCiphertextBytes[i] ^ XorString[i]);
        }

        // let's print this result to the command line to show that we know her plaintext
        string BobFindsOutAlicesPlaintextString = Encoding.UTF8.GetString(BobFindsOutAlicesPlaintext);

        Console.WriteLine("The result of Bob's 'hard' work? '" + BobFindsOutAlicesPlaintextString + "'");
        Console.WriteLine("was Bob successful? '" + (BobFindsOutAlicesPlaintextString == AlicePlaintext) + "'");

        Console.ReadLine();

    }
}