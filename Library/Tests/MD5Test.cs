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
        public void EncryptDecryptMD5()
        {
            string phrase1 = "data to crypt (long long test string)";
            string hashedPhrase1 = "ab7b7c33d4b61b50e2e5559f22b97cea";

            string phrase2 = "small";
            string hashedPhrase2 = "eb5c1399a871211c7e7ed732d15e3a8b";

            MemoryStream sourceStream = new MemoryStream(phrase1.ConvertToByteArray());
            MemoryStream hashedStream = new MemoryStream();

            CypherMD5 md5 = new CypherMD5();

            md5.HashStream(sourceStream, hashedStream);

            byte[] buf = new byte[hashedStream.Length];
            hashedStream.Read(buf, 0, (int)hashedStream.Length);

            Assert.AreEqual(hashedPhrase1, buf.ConvertToString());

            //

            sourceStream = new MemoryStream(phrase2.ConvertToByteArray());
            hashedStream = new MemoryStream();

            md5.HashStream(sourceStream, hashedStream);

            buf = new byte[hashedStream.Length];
            hashedStream.Read(buf, 0, (int)hashedStream.Length);

            Assert.AreEqual(hashedPhrase2, buf.ConvertToString());
        }
    }
}
