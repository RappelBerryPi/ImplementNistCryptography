using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Unicode;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Logging;

public class Program {
    public static void Main(string[] args) {
        const string library = "E:\\SoftHSM2\\lib\\softhsm2-x64.dll";
        // const string library = "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll";
        Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

        using IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, library, AppType.SingleThreaded);
        ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent).First();
        using ISession session = slot.OpenSession(SessionType.ReadWrite);
        session.Login(CKU.CKU_USER, args[0]);

        ILibraryInfo libraryInfo = pkcs11Library.GetInfo();
        ISlotInfo slotInfo = slot.GetSlotInfo();
        ISessionInfo sessionInfo = session.GetSessionInfo();

        Console.WriteLine("Library info:");
        Console.WriteLine($"\tManufacturer ID     - {libraryInfo.ManufacturerId}");
        Console.WriteLine($"\tLibrary Description - {libraryInfo.LibraryDescription}");
        Console.WriteLine($"\tLibrary Version     - {libraryInfo.LibraryVersion}");
        Console.WriteLine($"\tCryptoki Version    - {libraryInfo.CryptokiVersion}");
        Console.WriteLine();

        Console.WriteLine("Slot info:");
        Console.WriteLine($"\tManufacturer ID   - {slotInfo.ManufacturerId}");
        Console.WriteLine($"\tSlot ID           - {slotInfo.SlotId}");
        Console.WriteLine($"\tHardware Version  - {slotInfo.HardwareVersion}");
        Console.WriteLine($"\tFirmware Version  - {slotInfo.FirmwareVersion}");
        Console.WriteLine($"\tSlot Description  - {slotInfo.SlotDescription}");
        Console.WriteLine($"\tSlot Flags (isHW) - {slotInfo.SlotFlags.HardwareSlot}"); //?????
        Console.WriteLine($"\tSlot Flags (isRM) - {slotInfo.SlotFlags.RemovableDevice}"); //?????
        Console.WriteLine($"\tSlot Flags (isPr) - {slotInfo.SlotFlags.TokenPresent}"); //?????
        Console.WriteLine($"\tSlot Mechanisms:");
        List<CKM> mechanismList = slot.GetMechanismList();
        foreach (CKM mechanism1 in mechanismList) {
            IMechanismInfo mechanismInfo = slot.GetMechanismInfo(mechanism1);
            Console.WriteLine($"\t\t{mechanism1}");
            // TODO: more
        }
        Console.WriteLine();

        Console.WriteLine("Session info:");
        Console.WriteLine($"\tSlot ID       - {sessionInfo.SlotId}");
        Console.WriteLine($"\tState         - {sessionInfo.State}");
        Console.WriteLine($"\tSession ID    - {sessionInfo.SessionId}");
        Console.WriteLine($"\tSession Flags - {sessionInfo.SessionFlags}");
        Console.WriteLine($"\tDevice Error  - {sessionInfo.DeviceError}");


        List<IObjectAttribute> objectAttributes = [session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY)];
        List<IObjectHandle> objList = session.FindAllObjects(objectAttributes);
        List<CKA> infoList = [CKA.CKA_LABEL, CKA.CKA_ID];
        foreach (IObjectHandle objectHandle in objList) {
            List<IObjectAttribute> attributes1 = session.GetAttributeValue(objectHandle, infoList);
            string label = attributes1[0].GetValueAsString();
            string id = Convert.ToBase64String(attributes1[1].GetValueAsByteArray());
            Console.WriteLine($"{id} - {label}");
            Console.WriteLine();
        }

        objectAttributes = [session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)];
        objList = session.FindAllObjects(objectAttributes);
        infoList = [CKA.CKA_LABEL, CKA.CKA_ID];
        foreach (IObjectHandle objectHandle in objList) {
            List<IObjectAttribute> attributes1 = session.GetAttributeValue(objectHandle, infoList);
            string label = attributes1[0].GetValueAsString();
            string id = Convert.ToBase64String(attributes1[1].GetValueAsByteArray());
            Console.WriteLine($"{id} - {label}");
            Console.WriteLine();
        }

        /* now that we have a list of our secret keys, let's go ahead and find a way to export them. We're using ECDH1 because Thales K7 can support this if possible */
        byte[] ckaId = session.GenerateRandom(20);

        IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_EC_KEY_PAIR_GEN);

        List<IObjectAttribute> publicKeyAttributes = new List<IObjectAttribute>();
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY)); //allotted
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC)); //allotted
        publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, new byte[]
                                    { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 })); //p-256 OID
        //attempting to comment out unnecessary
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_COPYABLE, false));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DESTROYABLE, true));
        publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, false));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, false));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, false));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, false));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, false));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, false));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, false));
        //publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, false));
        publicKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "TKEK"));

        List<IObjectAttribute> privateKeyAttributes = new List<IObjectAttribute>();
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, new byte[]
        //                            { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 })); //p-256 OID // must be specified in public key as per PKCS#11 3.0
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_COPYABLE, false));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, false));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DESTROYABLE, true));
        privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId));
        privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "TKEK"));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, false));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, false));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, false));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, false));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, false));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, true));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, false));
        //privateKeyAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, false));

        //session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out var pub, out var priv);

        List<IObjectAttribute> attributes;
        //List<IObjectAttribute> attributes = session.GetAttributeValue(pub, [CKA.CKA_PUBLIC_KEY_INFO]);
        //byte[] publicKey = attributes[0].GetValueAsByteArray();

        //ECDiffieHellmanCngPublicKey publicKey1 = (ECDiffieHellmanCngPublicKey)ECDiffieHellmanCngPublicKey.FromByteArray(publicKey, CngKeyBlobFormat.EccPublicBlob);

        /* now that we've created this, let's go ahead and create an ECDH keypair inside of just a regular program, import the private key, export the public key,
         * derive the shared AES key, and then encrypt the keys to export into an SCM
         */

        ECDiffieHellman diffieHellman = new ECDiffieHellmanCng();
        //byte[] secretSharedKey = diffieHellman.DeriveKeyMaterial(publicKey1);
        //Console.WriteLine(Convert.ToBase64String(secretSharedKey));
        return;

        /* public key */
        /*
        List<IObjectAttribute> objectAttributes = [session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY)];
        List<IObjectHandle> objList = session.FindAllObjects(objectAttributes);
        List<CKA> infoList = [CKA.CKA_LABEL, CKA.CKA_ID];
        */
        objectAttributes = [session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY)];
        objList = session.FindAllObjects(objectAttributes);
        infoList = [CKA.CKA_LABEL, CKA.CKA_ID];
        foreach (IObjectHandle objectHandle in objList) {
            List<IObjectAttribute> attributes1 = session.GetAttributeValue(objectHandle, infoList);
            string label = attributes1[0].GetValueAsString();
            string id = Convert.ToBase64String(attributes1[1].GetValueAsByteArray());
            Console.WriteLine($"{id} - {label}");
            Console.WriteLine();
        }

        /* private keys */
        objectAttributes = [session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)];
        objList = session.FindAllObjects(objectAttributes);
        infoList = [CKA.CKA_LABEL, CKA.CKA_ID, CKA.CKA_TOKEN];
        foreach (IObjectHandle objectHandle in objList) {
            List<IObjectAttribute> attributes1 = session.GetAttributeValue(objectHandle, infoList);
            string label = attributes[0].GetValueAsString();
            string id = Convert.ToBase64String(attributes1[1].GetValueAsByteArray());
            bool isToken = attributes1[2].GetValueAsBool();
            Console.WriteLine($"{id} - {label} - isToken: {isToken}");
            Console.WriteLine();
        }

        /* public certificate */
        objectAttributes = [session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE)];
        objList = session.FindAllObjects(objectAttributes);
        infoList = [CKA.CKA_LABEL, CKA.CKA_ID, CKA.CKA_SUBJECT];
        foreach (IObjectHandle objectHandle in objList) {
            List<IObjectAttribute> attributes1 = session.GetAttributeValue(objectHandle, infoList);
            string label = attributes1[0].GetValueAsString();
            string id = Convert.ToBase64String(attributes1[1].GetValueAsByteArray());
            string subject = Convert.ToBase64String(attributes1[2].GetValueAsByteArray());
            Console.WriteLine($"{id} - {label} - {subject}");
            Console.WriteLine();
        }



        //List<CKA> infoList = [CKA.CKA_VALUE, CKA.CKA_LABEL, CKA.CKA_ID];
        //Console.WriteLine(Convert.ToBase64String(attributes[0].GetValueAsByteArray()));
    }
}