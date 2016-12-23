using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptoLibrary;
using System.IO;

namespace CryptoLibrary.MD5Test
{
    [TestClass]
    public class GhostTest
    {
        [TestMethod]
        public void EncryptDecriptEquals()
        {
            string sourceDataString = "some data";

            MemoryStream sourceDataStream = new MemoryStream(Encoding.Default.GetBytes(sourceDataString));
            MemoryStream encryptedDataStream = new MemoryStream();
            MemoryStream decryptedDataStream = new MemoryStream();

            GOST28147_89 gost = new GOST28147_89();
            gost.Encrypt(sourceDataStream, encryptedDataStream);
            gost.Decrypt(encryptedDataStream, decryptedDataStream);

            string decryptedDataString = Encoding.Default.GetString(decryptedDataStream.ToArray()).TrimEnd('\0');
            Assert.AreEqual(sourceDataString, decryptedDataString);
        }

        [TestMethod]
        public void EncryptDecryptDifferentLength()
        {
            string sourceDataStringLong = "Some extremely important data to encrypt by GOST algorithm";
            string sourceDataStringShort = "data";
            string sourceDataStringSymbol = "s";
            string decryptedDataString;

            GOST28147_89 gost = new GOST28147_89();
            MemoryStream sourceDataStream = new MemoryStream(Encoding.Default.GetBytes(sourceDataStringLong));
            MemoryStream encryptedDataStream = new MemoryStream();
            gost.Encrypt(sourceDataStream, encryptedDataStream);

            MemoryStream decryptedDataStream = new MemoryStream();
            gost.Decrypt(encryptedDataStream, decryptedDataStream);

            decryptedDataString = Encoding.Default.GetString(decryptedDataStream.ToArray()).TrimEnd('\0');
            Assert.AreEqual(sourceDataStringLong, decryptedDataString);

            sourceDataStream = new MemoryStream(Encoding.Default.GetBytes(sourceDataStringShort));
            encryptedDataStream = new MemoryStream();
            decryptedDataStream = new MemoryStream();

            gost.Encrypt(sourceDataStream, encryptedDataStream);
            gost.Decrypt(encryptedDataStream, decryptedDataStream);

            decryptedDataString = Encoding.Default.GetString(decryptedDataStream.ToArray()).TrimEnd('\0');
            Assert.AreEqual(sourceDataStringShort, decryptedDataString);

            sourceDataStream = new MemoryStream(Encoding.Default.GetBytes(sourceDataStringSymbol));
            encryptedDataStream = new MemoryStream();
            decryptedDataStream = new MemoryStream();

            gost.Encrypt(sourceDataStream, encryptedDataStream);
            gost.Decrypt(encryptedDataStream, decryptedDataStream);

            decryptedDataString = Encoding.Default.GetString(decryptedDataStream.ToArray()).TrimEnd('\0');
            Assert.AreEqual(sourceDataStringSymbol, decryptedDataString);
        }

    }
}
