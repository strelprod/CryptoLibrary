using System;
using System.Text;
using System.Collections.Generic;

using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptoLibrary;
using System.IO;

namespace CryptoLibrary.Tests
{
    [TestClass]
    public class MD5Test
    {
        [TestMethod]
        public void HashMD5Long()
        {
            string phrase1 = "data to crypt (long long test string)";
            string hashedPhrase1 = "ab7b7c33d4b61b50e2e5559f22b97cea";

            MemoryStream sourceStream = new MemoryStream(phrase1.ConvertToByteArray());
            MemoryStream hashedStream = new MemoryStream();

            MD5 md5 = new MD5();

            md5.HashStream(sourceStream, hashedStream);

            byte[] buf = new byte[hashedStream.Length];
            hashedStream.Read(buf, 0, (int)hashedStream.Length);

            Assert.AreEqual(hashedPhrase1, buf.ConvertToString());
        }

        [TestMethod]
        public void HashMD5Small()
        {
            string phrase2 = "small";
            string hashedPhrase2 = "eb5c1399a871211c7e7ed732d15e3a8b";

            MemoryStream sourceStream = new MemoryStream(phrase2.ConvertToByteArray());
            MemoryStream hashedStream = new MemoryStream();

            MD5 md5 = new MD5();

            md5.HashStream(sourceStream, hashedStream);

            byte[] buf = new byte[hashedStream.Length];
            hashedStream.Read(buf, 0, (int)hashedStream.Length);

            Assert.AreEqual(hashedPhrase2, buf.ConvertToString());
        }
    }
}
