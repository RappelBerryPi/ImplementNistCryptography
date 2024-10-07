using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace RSA_v_ECC_Sig__Framework_ {
    internal class Program {
        static void Main(string[] args) {
            string StringToSign = "abc";
            byte[] ByteStringToSign = Encoding.UTF8.GetBytes(StringToSign);

            /* RSA 2048 */
            RSA rsa = RSA.Create(2048);
            DateTime start = DateTime.Now;
            for (int i = 0; i < 10000; i++) {
                rsa.SignData(ByteStringToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            }
            DateTime finish = DateTime.Now;
            TimeSpan lapse = finish - start;
            TimeSpan lapse1 = Process.GetCurrentProcess().TotalProcessorTime;
            Console.WriteLine("RSA 2048 Run Time: " + lapse);
            Console.WriteLine("RSA 2048 Run Time (CPU): " + lapse1);

            /* RSA 3072 */
            rsa = RSA.Create(3072);
            start = DateTime.Now;
            for (int i = 0; i < 10000; i++) {
                rsa.SignData(ByteStringToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            }
            finish = DateTime.Now;
            lapse = finish - start;
            TimeSpan lapse2 = Process.GetCurrentProcess().TotalProcessorTime;
            Console.WriteLine("RSA 3072 Run Time: " + lapse);
            Console.WriteLine("RSA 3072 Run Time (CPU): " + (lapse2 - lapse1));

            /* ECC 384 */
            ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            start = DateTime.Now;
            for (int i = 0; i < 10000; i++) {
                ecdsa.SignData(ByteStringToSign, HashAlgorithmName.SHA256);
            }
            finish = DateTime.Now;
            lapse = finish - start;
            TimeSpan lapse3 = Process.GetCurrentProcess().TotalProcessorTime;
            Console.WriteLine("ECC 384  Run Time: " + lapse);
            Console.WriteLine("ECC 384  Run Time (CPU): " + (lapse3 - lapse2));

            /* ECC 521 */
            ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);
            start = DateTime.Now;
            for (int i = 0; i < 10000; i++) {
                ecdsa.SignData(ByteStringToSign, HashAlgorithmName.SHA256);
            }
            finish = DateTime.Now;
            lapse = finish - start;
            TimeSpan lapse4 = Process.GetCurrentProcess().TotalProcessorTime;
            Console.WriteLine("ECC 521  Run Time: " + lapse);
            Console.WriteLine("ECC 521  Run Time (CPU): " + (lapse4 - lapse3));
        }
    }
}

