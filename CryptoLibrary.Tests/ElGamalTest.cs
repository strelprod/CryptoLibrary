using System;
using System.Text;
using System.Collections.Generic;

using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CryptoLibrary;
using System.IO;

namespace CryptoLibrary.MD5Test
{
    [TestClass]
    public class ElGamalTest
    {
        [TestMethod]
        public void EncryptDecryptEqualsElGamal()
        {
            string sourceString = "vladimir";
            ElGamal elGamal = new ElGamal();
            MemoryStream sourceStream = new MemoryStream(Encoding.Default.GetBytes(sourceString));
            MemoryStream encryptedStream = new MemoryStream();
            MemoryStream decryptedStream = new MemoryStream();

            elGamal.Encrypt(sourceStream, encryptedStream);
            elGamal.Decrypt(encryptedStream, decryptedStream);

            string decryptedString = Encoding.Default.GetString(decryptedStream.ToArray()).TrimEnd('\0');
            Assert.AreEqual(sourceString, decryptedString);
        }

        [TestMethod]
        public void EncryptDecryptLongStringElGamal()
        {
            string sourceString = "vladimir strelnikov";
            string decryptedString;
            ElGamal elGamal = new ElGamal();
            MemoryStream sourceStream = new MemoryStream(Encoding.Default.GetBytes(sourceString));
            MemoryStream encryptedStream = new MemoryStream();
            MemoryStream decryptedStream = new MemoryStream();

            elGamal.Encrypt(sourceStream, encryptedStream);
            elGamal.Decrypt(encryptedStream, decryptedStream);

            decryptedString = Encoding.Default.GetString(decryptedStream.ToArray()).TrimEnd('\0');
            Assert.AreEqual(sourceString, decryptedString);
        }

        [TestMethod]
        public void EncryptDecryptShortStringElGamal()
        {
            string sourceString = "strel";
            string decryptedString;
            ElGamal elGamal = new ElGamal();
            MemoryStream sourceStream = new MemoryStream(Encoding.Default.GetBytes(sourceString));
            MemoryStream decryptedStream = new MemoryStream();
            MemoryStream encryptedStream = new MemoryStream();

            elGamal.Encrypt(sourceStream, encryptedStream);
            elGamal.Decrypt(encryptedStream, decryptedStream);

            decryptedString = Encoding.Default.GetString(decryptedStream.ToArray()).TrimEnd('\0');
            Assert.AreEqual(sourceString, decryptedString);
        }
    }
}
