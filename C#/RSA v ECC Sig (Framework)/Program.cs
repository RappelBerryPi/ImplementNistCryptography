using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace RSA_v_ECC_Sig__Framework_ {
    internal class Program {
        static RSA rsa;
        static ECDsa ecdsa;

        static void Main(string[] args) {
            Func<byte[], HashAlgorithmName, byte[]> signFunction = RSASign;
            Action<byte[], byte[], HashAlgorithmName> verifyFunction = RSAVerify;
            rsa = RSA.Create(2048);
            loop(signFunction, verifyFunction, HashAlgorithmName.SHA256, "RSA 2048");

            rsa = RSA.Create(3072);
            loop(signFunction, verifyFunction, HashAlgorithmName.SHA256, "RSA 3072");

            signFunction = EcDsaSign;
            verifyFunction = EcDsaVerify;
            ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            loop(signFunction, verifyFunction, HashAlgorithmName.SHA256, "ECC 384 ");

            ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);
            loop(signFunction, verifyFunction, HashAlgorithmName.SHA512, "ECC 521 ");
        }

        static byte[] RSASign(byte[] ByteStringToSign, HashAlgorithmName hashAlgorithmName) {
            return rsa.SignData(ByteStringToSign, hashAlgorithmName, RSASignaturePadding.Pss);
        }

        static byte[] EcDsaSign(byte[] ByteStringToSign, HashAlgorithmName hashAlgorithmName) {
            return ecdsa.SignData(ByteStringToSign, hashAlgorithmName);
        }
        static void RSAVerify(byte[] data, byte[] signature, HashAlgorithmName hashAlgorithmName) {
            rsa.VerifyData(data, signature, hashAlgorithmName, RSASignaturePadding.Pss);
        }

        static void EcDsaVerify(byte[] data, byte[] signature, HashAlgorithmName hashAlgorithmName) {
            ecdsa.VerifyData(data, signature, hashAlgorithmName);
        }

        static void loop(Func<byte[], HashAlgorithmName, byte[]> signFunction,
                         Action<byte[], byte[], HashAlgorithmName> verifyFunction,
                         HashAlgorithmName hashAlgorithmName, 
                         string Description) {
            List<TimeSpan> lapses = new List<TimeSpan>();
            List<TimeSpan> CpuLapses = new List<TimeSpan>();
            string StringToSign = "abc";
            byte[] ByteStringToSign = Encoding.UTF8.GetBytes(StringToSign);
            List<byte[]> signatures = new List<byte[]>(); 

            Process CurrentProcess = Process.GetCurrentProcess();
            int lapseCounter = CpuLapses.Count;
            CpuLapses.Add(CurrentProcess.TotalProcessorTime);
            int signatureCount = 10000;

            for (int loop = 0; loop < 5; loop++) {
                DateTime start = DateTime.Now;
                TimeSpan startCpu = CurrentProcess.TotalProcessorTime;
                for (int i = 0; i < signatureCount; i++) {
                    byte[] signature = signFunction(ByteStringToSign, hashAlgorithmName);
                    signatures.Add(signature); // make a local thing
                }
                DateTime finish = DateTime.Now;
                lapses.Add(finish - start);
                CpuLapses.Add(CurrentProcess.TotalProcessorTime - startCpu);
                lapseCounter++;
                Console.WriteLine($"Time to Sign {signatureCount} Signatures for {Description}: {lapses[lapses.Count - 1]}");
                Console.WriteLine($"CPU Time to Sign {signatureCount} Signatures for {Description}: {CpuLapses[CpuLapses.Count - 1]}");

                start = DateTime.Now;
                startCpu = CurrentProcess.TotalProcessorTime;
                // validate the signatures in this block
                for (int i = 0; i < signatureCount; i++) {
                    verifyFunction(ByteStringToSign, signatures[i], hashAlgorithmName);
                }
                finish = DateTime.Now;
                lapses.Add(finish - start);
                CpuLapses.Add(CurrentProcess.TotalProcessorTime - startCpu);
                lapseCounter++;
                Console.WriteLine($"Time to Verify {signatureCount} Signatures for {Description}: {lapses[lapses.Count - 1]}");
                Console.WriteLine($"CPU Time to Verify {signatureCount} Signatures for {Description}: {CpuLapses[CpuLapses.Count - 1]}");
                Console.WriteLine();
            }

            double avgSign = (lapses[0] + lapses[2] + lapses[4] + lapses[6] + lapses[8]).TotalSeconds / 5;
            double avgVerify = (lapses[1] + lapses[3] + lapses[5] + lapses[7] + lapses[9]).TotalSeconds / 5;
            double avgCpuSign = (CpuLapses[0] + CpuLapses[2] + CpuLapses[4] + CpuLapses[6] + CpuLapses[8]).TotalSeconds / 5;
            double avgCpuVerify = (CpuLapses[1] + CpuLapses[3] + CpuLapses[5] + CpuLapses[7] + CpuLapses[9]).TotalSeconds / 5;

            Console.WriteLine($"Average Time (over 5 iterations) to Sign {signatureCount} Signatures for {Description}: {avgSign:0.##}");
            Console.WriteLine($"Average CPU Time (over 5 iterations) to Sign {signatureCount} Signatures for {Description}: {avgCpuSign:0.##}");
            Console.WriteLine($"Average Time (over 5 iterations) to Verify {signatureCount} Signatures for {Description}: {avgVerify:0.##}");
            Console.WriteLine($"Average CPU Time (over 5 iterations) to Verify {signatureCount} Signatures for {Description}: {avgCpuVerify:0.##}");

            double SignsPerSecond = 10000 / avgSign;
            double CpuSignsPerSecond = 10000 / avgCpuSign;
            double VerifiesPerSecond = 10000 / avgVerify;
            double CpuVerifiesPerSecond = 10000 / avgCpuVerify;

            Console.WriteLine($"{Description} Signs/s: {SignsPerSecond:0.#}");
            Console.WriteLine($"{Description} CPU Signs/s: {CpuSignsPerSecond:0.#}");
            Console.WriteLine($"{Description} Verifies/s: {VerifiesPerSecond:0.#}");
            Console.WriteLine($"{Description} CPU Verifies/s: {CpuVerifiesPerSecond:0.#}");
        }
    }
}
