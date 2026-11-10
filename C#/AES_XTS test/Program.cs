using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AES_XTS_test {
    public enum ASC_DESC {
        ASC,
        DESC
    }

    internal class Program {
        public string SortString { get; set; }
        static void Main(string[] args) {
            // byte[] key = { 0x80, 0x73, 0xf0, 0x18, 0xd4, 0x0f, 0xd8, 0xb7, 0x7e, 0xb4, 0x9a, 0x12, 0x6b, 0x54, 0x53, 0x97, 0x36, 0x20, 0xd5, 0x17, 0xea, 0x5b, 0x0d, 0x4a, 0x9d, 0x36, 0x19, 0xcb, 0x98, 0x69, 0xc3, 0xee };
            // byte[] Tweak = { 0x75, 0x6d, 0x02, 0x70, 0xf2, 0x5b, 0xf0, 0x8f, 0x07, 0x7b, 0x7e, 0x62, 0x23, 0xef, 0xa1, 0x37 };
            // byte[] Plaintext = { 0x59, 0xa6, 0xd9, 0x1b, 0x83, 0xbf, 0x81, 0x81, 0xdf, 0xda, 0xbf, 0xe2, 0xb9, 0xa9, 0x25, 0x89, 0x00 }; // this is 17 bytes (136 bits)
            // Aes aes = Aes.Create();
            // aes.Mode = CipherMode.XTS; // unsupported

            List<Program> programs = new List<Program>();
            for (int i = 0; i < 100; i++) {
                Program program = new Program();
                byte[] bytes = new byte[16];
                RandomNumberGenerator.Create().GetNonZeroBytes(bytes);
                program.SortString = Convert.ToBase64String(bytes);
                programs.Add(program);
            }
            //var x = programs.AsQueryable().OrderBy(y => "SortString").ToList();
            PropertyInfo x = typeof(Program).GetProperty("SortString");
            ASC_DESC asc_desc = ASC_DESC.ASC;

            string column = "...";
            //PropertyInfo x = typeof([Class]).GetProperty(column);
            IQueryable<Program> abc = programs.AsQueryable();
            if (asc_desc == ASC_DESC.ASC) {
                abc = abc.OrderBy(z => x.GetValue(z));
            } else { 
                abc = abc.OrderByDescending(z => x.GetValue(z));
            }
            List<Program> values = abc.ToList();


            if (x != null) {
                //var y = programs.AsQueryable().OrderBy(z => x.GetValue(z)).ToList();
                foreach (Program program in values) {
                    Console.WriteLine(program.SortString);
                }
            } else {
                Console.WriteLine("no such column");
            }
            Console.ReadLine();


        }
    }
}
