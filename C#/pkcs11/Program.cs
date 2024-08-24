using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Unicode;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Logging;
using Net.Pkcs11Interop.LowLevelAPI40.MechanismParams;

public class Program {
    public static void Main(string[] args) {
        // before running this, please run "softhsm2-util --init-token --slot ... --so-pin .... --label '....'"
        // this will reset everything to make sure that this will work properly

        // set up the library and open the slot
        const string library = "E:\\SoftHSM2\\lib\\softhsm2-x64.dll";
        Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
        using IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, library, AppType.SingleThreaded);
        ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent).First();
        using ISession session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, args[0]);


        /* let's create an AES key that we can use for encryption and decryption of various ciphertexts */
        IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_AES_KEY_GEN);
        List<IObjectAttribute> secretKeyAttributes = new List<IObjectAttribute>();
        secretKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
        secretKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_AES));
        secretKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE_LEN, 32));
        secretKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "AES_KEY"));
        secretKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0, 0, 1, 0}));
        IObjectHandle secretKey =  session.GenerateKey(mechanism, secretKeyAttributes);

        /* bad, don't do this, use a better mode with a proper IV */
        mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_AES_ECB);

        byte[] cipherText = session.Encrypt(mechanism, secretKey, Encoding.UTF8.GetBytes("abcdefghijklmnop"));

        /* now that we have our ciphertext, let's create a TKEK using ECDH (P-256) */
        /* This will involve being albe to export the public key from the HSM, */
        /* we will also need to import the public key from CNG, create an AES TKEK, and then use that to wrap the AES key */
        /* let's create a random export key and use that key to export out our encryption keys*/
        byte[] ckaId = session.GenerateRandom(20);

        mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_EC_KEY_PAIR_GEN);

        List<IObjectAttribute> publicKeyAttributes = new List<IObjectAttribute>();
        publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY)); //allotted
        publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC)); //allotted
        publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, new byte[]
                                    { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 })); //p-256 OID
        publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
        publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
        publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "TKEK"));
        publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
        publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DESTROYABLE, true));

        List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>();
        privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
        privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "TKEK"));
        // required otherwise the key cannot be used to derive other keys
        privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, true));

        session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out var pub, out var priv);

        List<IObjectAttribute> attributes;
        attributes = session.GetAttributeValue(pub, new List<CKA> {CKA.CKA_EC_POINT});
        if (attributes[0].CannotBeRead) {
            Console.WriteLine("somehow unable to print out the value of the public key?");
            return;
        }

        // THE EC point is the value Q in ASN.1 encoding. When this is P-256 it's a 67 byte value. 
        // the first three bytes of ASN.1 tell the type and length of the actual Value. 
        // Q itself is a perfect split of 32 bytes of point[X], and 32 bytes of point[Y]. 
        // D is the secret key value, which we don't care about because that's supposed to remain hidden in the HSM. 
        byte[] publicKey = attributes[0].GetValueAsByteArray();
        ECDiffieHellman publicKey1 = ECDiffieHellman.Create(new ECParameters {
            Curve = ECCurve.NamedCurves.nistP256,
            D = null,
            Q = new ECPoint {
                X = publicKey.Skip(3).Take(32).ToArray(),
                Y = publicKey.Skip(35).ToArray()
            }
        });

        /* now that we've created this, let's go ahead and create an ECDH keypair inside of just a regular program, import the private key, export the public key,
         * derive the shared AES key, and then encrypt the keys to export into an SCM
         */

        ECDiffieHellman diffieHellman = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP256);
        byte[] secretSharedKey = diffieHellman.DeriveKeyMaterial(publicKey1.PublicKey);
        //Console.WriteLine(Convert.ToBase64String(secretSharedKey));

        // now that we have the derived secret key on the CNG side, let's do the same on the HSM side

        ECPoint Q2 = diffieHellman.PublicKey.ExportParameters().Q;
        // byte[] otherPublicKey = new byte[67];
        List<byte> otherpublicKeyList = new List<byte>();
        otherpublicKeyList.Add(4);
        otherpublicKeyList.Add(65);
        otherpublicKeyList.Add(4);
        otherpublicKeyList.AddRange(Q2.X);
        otherpublicKeyList.AddRange(Q2.Y);
        byte[] otherpublicKey = otherpublicKeyList.ToArray();
        var m = session.Factories.MechanismParamsFactory.CreateCkEcdh1DeriveParams((ulong)CKD.CKD_SHA256_KDF, [1, 2, 3, 4], otherpublicKey);
        mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_ECDH1_DERIVE, m);
        secretKeyAttributes = new List<IObjectAttribute>();
        secretKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY));
        secretKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_AES));
        secretKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE_LEN, 32));
        secretKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "AES_KEY_TKEK"));
        secretKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0, 0, 2, 0}));

        //below is failing. why?
        IObjectHandle sharedKeyInHSM = session.DeriveKey(mechanism, priv, secretKeyAttributes);
            
        return;
    }
}