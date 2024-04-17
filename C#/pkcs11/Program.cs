using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Unicode;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Logging;

public class Program {
    public static void Main(string[] args) {
        const string library = "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll";
        Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

        using IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, library, AppType.SingleThreaded);
        ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent).First();
        using ISession session = slot.OpenSession(SessionType.ReadOnly);
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
        foreach (CKM mechanism in mechanismList) {
            IMechanismInfo mechanismInfo = slot.GetMechanismInfo(mechanism);
            Console.WriteLine($"\t\t{mechanism}");
            // TODO: more
        }
        Console.WriteLine();

        Console.WriteLine("Session info:");
        Console.WriteLine($"\tSlot ID       - {sessionInfo.SlotId}");
        Console.WriteLine($"\tState         - {sessionInfo.State}");
        Console.WriteLine($"\tSession ID    - {sessionInfo.SessionId}");
        Console.WriteLine($"\tSession Flags - {sessionInfo.SessionFlags}");
        Console.WriteLine($"\tDevice Error  - {sessionInfo.DeviceError}");



        byte[] random = session.GenerateRandom(20);
        Console.WriteLine(Convert.ToBase64String(random));
        return;

        /* public key */
        List<IObjectAttribute> objectAttributes = [session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY)];
        List<IObjectHandle> objList = session.FindAllObjects(objectAttributes);
        List<CKA> infoList = [CKA.CKA_LABEL, CKA.CKA_ID];
        foreach (IObjectHandle objectHandle in objList) {
            List<IObjectAttribute> attributes = session.GetAttributeValue(objectHandle, infoList);
            string label = attributes[0].GetValueAsString();
            string id = Convert.ToBase64String(attributes[1].GetValueAsByteArray());
            Console.WriteLine($"{id} - {label}");
            Console.WriteLine();
        }

        /* private keys */
        objectAttributes = [session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)];
        objList = session.FindAllObjects(objectAttributes);
        infoList = [CKA.CKA_LABEL, CKA.CKA_ID, CKA.CKA_TOKEN];
        foreach (IObjectHandle objectHandle in objList) {
            List<IObjectAttribute> attributes = session.GetAttributeValue(objectHandle, infoList);
            string label = attributes[0].GetValueAsString();
            string id = Convert.ToBase64String(attributes[1].GetValueAsByteArray());
            bool isToken = attributes[2].GetValueAsBool();
            Console.WriteLine($"{id} - {label} - isToken: {isToken}");
            Console.WriteLine();
        }

        /* public certificate */
        objectAttributes = [session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE)];
        objList = session.FindAllObjects(objectAttributes);
        infoList = [CKA.CKA_LABEL, CKA.CKA_ID, CKA.CKA_SUBJECT];
        foreach (IObjectHandle objectHandle in objList) {
            List<IObjectAttribute> attributes = session.GetAttributeValue(objectHandle, infoList);
            string label = attributes[0].GetValueAsString();
            string id = Convert.ToBase64String(attributes[1].GetValueAsByteArray());
            string subject = Convert.ToBase64String(attributes[2].GetValueAsByteArray());
            Console.WriteLine($"{id} - {label} - {subject}");
            Console.WriteLine();
        }



        //List<CKA> infoList = [CKA.CKA_VALUE, CKA.CKA_LABEL, CKA.CKA_ID];
        //Console.WriteLine(Convert.ToBase64String(attributes[0].GetValueAsByteArray()));
    }
}