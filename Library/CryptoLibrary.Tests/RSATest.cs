using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using CryptoLibrary;
using System.Text;

namespace RSATest
{
    [TestClass]
    public class RSATest
    {
        [TestMethod]
        public void SignAndVerify()
        {
            string sourceDataString = "Test data";
            MemoryStream input = new MemoryStream(Encoding.Default.GetBytes(sourceDataString));
            MemoryStream output = new MemoryStream();

            RSASign rsa = new RSASign();
            rsa.Sign(input, output);

            Assert.IsTrue(rsa.Verify(output));
        }
    }
}
