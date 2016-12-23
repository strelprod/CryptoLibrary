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
    public class GhostTest
    {
        [TestMethod]
        public void EncryptDecriptEquals()
        {
            string sourceDataString = "some data";
            string decryptedDataString;

            GOSTLib.GostProvider gost = new GOSTLib.GostProvider();
            MemoryStream sourceDataStream = new MemoryStream(Encoding.Default.GetBytes(sourceDataString));
            MemoryStream encryptedDataStream = gost.EncryptData(sourceDataStream);
            MemoryStream decryptedDataStream = gost.DecryptData(encryptedDataStream);

            decryptedDataString = Encoding.Default.GetString(decryptedDataStream.ToArray()).TrimEnd('\0');
            Assert.AreEqual(sourceDataString, decryptedDataString);
        }

        [TestMethod]
        public void EncryptOtherLibEquals()
        {
            string sourceDataString = "Some extremely important data to encrypt";
            string encryptedDataString;

            GOSTLib.GostProvider gost = new GOSTLib.GostProvider();
            MemoryStream sourceDataStream = new MemoryStream(Encoding.Default.GetBytes(sourceDataString));
            MemoryStream encryptedDataStream = gost.EncryptData(sourceDataStream);
            encryptedDataString = Encoding.Default.GetString(encryptedDataStream.ToArray()).TrimEnd('\0');

            Assert.AreEqual(encryptedDataString, "\u0006lK—Џ\u0013\u0014З-nz Gu=В\aLВk}rш‹ГnЊВYГ\u0004Z^\u0004и\u0005GґЙ\u0012");
        }

        [TestMethod]
        public void EncryptDecryptDifferentLength()
        {
            string sourceDataStringLong = "Some extremely important data to encrypt by GOST algorithm";
            string sourceDataStringShort = "data";
            string sourceDataStringSymbol = "s";
            string decryptedDataString;

            GOSTLib.GostProvider gost = new GOSTLib.GostProvider();
            MemoryStream sourceDataStream = new MemoryStream(Encoding.Default.GetBytes(sourceDataStringLong));
            MemoryStream encryptedDataStream = gost.EncryptData(sourceDataStream);
            MemoryStream decryptedDataStream = gost.DecryptData(encryptedDataStream);

            decryptedDataString = Encoding.Default.GetString(decryptedDataStream.ToArray()).TrimEnd('\0');
            Assert.AreEqual(sourceDataStringLong, decryptedDataString);

            sourceDataStream = new MemoryStream(Encoding.Default.GetBytes(sourceDataStringShort));
            encryptedDataStream = gost.EncryptData(sourceDataStream);
            decryptedDataStream = gost.DecryptData(encryptedDataStream);
            decryptedDataString = Encoding.Default.GetString(decryptedDataStream.ToArray()).TrimEnd('\0');
            Assert.AreEqual(sourceDataStringShort, decryptedDataString);

            sourceDataStream = new MemoryStream(Encoding.Default.GetBytes(sourceDataStringSymbol));
            encryptedDataStream = gost.EncryptData(sourceDataStream);
            decryptedDataStream = gost.DecryptData(encryptedDataStream);
            decryptedDataString = Encoding.Default.GetString(decryptedDataStream.ToArray()).TrimEnd('\0');
            Assert.AreEqual(sourceDataStringSymbol, decryptedDataString);
        }

    }
}
