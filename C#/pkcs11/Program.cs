using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Unicode;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

public class Program {
    public static void Main(string[] args) {
        const string library = "C:\\Program Files\\Yubico\\Yubico PIV Tool\\bin\\libykcs11.dll";
        Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
        using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, library, AppType.SingleThreaded)) {
            ILibraryInfo libraryInfo = pkcs11Library.GetInfo();
            ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent).First();
            using (ISession session = slot.OpenSession(SessionType.ReadOnly)) {
                session.Login(CKU.CKU_USER, args[0]);

                List<IObjectAttribute> objectAttributes = [session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY)];

                IObjectHandle obj = session.FindAllObjects(objectAttributes).First();

                IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);
                byte[] data = Encoding.UTF8.GetBytes("Hello World");
                byte[] signature = new byte[] {};
                using (FileStream fileStream = File.OpenRead("testing.signature.txt")) {
                    byte[] readBytes = new byte[344];
                    int len = fileStream.Read(readBytes, 0, 344);
                    string signatureString = Encoding.UTF8.GetString(readBytes);
                    signature = Convert.FromBase64String(signatureString);
                }
                session.Verify(mechanism, obj, data, signature, out bool isValid);
                Console.WriteLine(isValid);
            }
        }
    }
}