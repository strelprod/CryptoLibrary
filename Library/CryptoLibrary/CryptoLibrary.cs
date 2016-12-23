using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace CryptoLibrary
{
    public interface ICrypto
    {
        void Encrypt(Stream input, Stream output);
        void Decrypt(Stream input, Stream output);
    }

    /// ГОСТ-28147-89   
    public class GOST28147_89 : ICrypto
    {
        private uint[] key;
        private uint[] standardKey = new uint[8] { 0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777, 0x88888888 };

        private static byte[] h8 = { 0x14, 0x04, 0x13, 0x01, 0x02, 0x15, 0x11, 0x08, 0x03, 0x10, 0x06, 0x12, 0x05, 0x09, 0x00, 0x07 };
        private static byte[] h7 = { 0x15, 0x01, 0x08, 0x14, 0x06, 0x11, 0x03, 0x04, 0x09, 0x07, 0x02, 0x13, 0x12, 0x00, 0x05, 0x10 };
        private static byte[] h6 = { 0x10, 0x00, 0x09, 0x14, 0x06, 0x03, 0x15, 0x05, 0x01, 0x13, 0x12, 0x07, 0x11, 0x04, 0x02, 0x08 };
        private static byte[] h5 = { 0x07, 0x13, 0x14, 0x03, 0x00, 0x06, 0x09, 0x10, 0x01, 0x02, 0x08, 0x05, 0x11, 0x12, 0x04, 0x15 };
        private static byte[] h4 = { 0x02, 0x12, 0x04, 0x01, 0x07, 0x10, 0x11, 0x06, 0x08, 0x05, 0x03, 0x15, 0x13, 0x00, 0x14, 0x09 };
        private static byte[] h3 = { 0x12, 0x01, 0x10, 0x15, 0x09, 0x02, 0x06, 0x08, 0x00, 0x13, 0x03, 0x04, 0x14, 0x07, 0x05, 0x11 };
        private static byte[] h2 = { 0x04, 0x11, 0x02, 0x14, 0x15, 0x00, 0x08, 0x13, 0x03, 0x12, 0x09, 0x07, 0x05, 0x10, 0x06, 0x01 };
        private static byte[] h1 = { 0x13, 0x02, 0x08, 0x04, 0x06, 0x15, 0x11, 0x01, 0x10, 0x09, 0x03, 0x14, 0x05, 0x00, 0x12, 0x07 };

        private byte[] h87 = new byte[256];
        private byte[] h65 = new byte[256];
        private byte[] h43 = new byte[256];
        private byte[] h21 = new byte[256];

        private static int bytesNumber = 4;

        public GOST28147_89()
        {
            SetKey(standardKey);
        }

        public void SetKey(uint[] newKey)
        {
            key = newKey;
        }

        public void SetOptimTable()
        {
            for (int i = 0; i < 256; i++)
            {
                h87[i] = (byte)(h8[i >> 4] << 4 | h7[i & 15]);
                h65[i] = (byte)(h6[i >> 4] << 4 | h5[i & 15]);
                h43[i] = (byte)(h4[i >> 4] << 4 | h3[i & 15]);
                h21[i] = (byte)(h2[i >> 4] << 4 | h1[i & 15]);
            }
        }

        private uint ReplaceWithTable(uint x)
        {
            x = (uint)(h87[x >> 24 & 255] << 24 | h65[x >> 16 & 255] << 16 |h43[x >> 8 & 255] << 8 | h21[x & 255]);

            return x << 11 | x >> (32 - 11);
        }

        public uint ByteArrToUint(byte[] source)
        {
            uint result = 0;
            for (int i = 0; i < source.Length; ++i)
                result = (uint)(result | (source[i] << (8 * i)));

            return result;
        }

        public void UintToByteArr(int start, int length, byte[] destination, uint source)
        {
            for (int i = 0; i < length; ++i)
            {
                destination[start + i] = (byte)((source & (0x000000FF << 8 * i)) >> 8 * i);
            }
        }

        public void GOSTBlockCrypt(uint[] planeDataBlock, uint[] encryptedDataBlck, uint[] key)
        {
            uint n1, n2;

            n1 = planeDataBlock[0];
            n2 = planeDataBlock[1];

            for (int i = 0; i < 3; ++i)
            {
                for (int j = 0; j < 7; j += 2)
                {
                    n2 ^= ReplaceWithTable(n1 + key[j]);
                    n1 ^= ReplaceWithTable(n2 + key[j + 1]);
                }
            }

            for (int i = 7; i > 0; i -= 2)
            {
                n2 ^= ReplaceWithTable(n1 + key[i]);
                n1 ^= ReplaceWithTable(n2 + key[i - 1]);
            }

            encryptedDataBlck[0] = n2;
            encryptedDataBlck[1] = n1;
        }

        public void GOSTBlockDecrypt(uint[] encryptedDataBlock, uint[] decryptedDataBlock, uint[] key)
        {
            uint n1, n2;

            n1 = encryptedDataBlock[0];
            n2 = encryptedDataBlock[1];

            for (int i = 0; i < 7; i += 2)
            {
                n2 ^= ReplaceWithTable(n1 + key[i]);
                n1 ^= ReplaceWithTable(n2 + key[i + 1]);
            }

            for (int i = 0; i < 3; ++i)
            {
                for (int j = 7; j > 0; j -= 2)
                {
                    n2 ^= ReplaceWithTable(n1 + key[j]);
                    n1 ^= ReplaceWithTable(n2 + key[j - 1]);
                }
            }

            decryptedDataBlock[0] = n2;
            decryptedDataBlock[1] = n1;
        }

        private void PlaneDataResize(ref byte[] planeData)
        {
            if (planeData.Length % 4 != 0)
            {
                int lenght = (planeData.Length / 4) * 4 + 4;
                Array.Resize<byte>(ref planeData, lenght);
            }

            if ((planeData.Length / 4) % 2 != 0)
                Array.Resize<byte>(ref planeData, planeData.Length + 4);
        }

        private void EncryptedDataResize(ref byte[] encryptedData)
        {
            if (encryptedData.Length % 4 != 0)
            {
                int lenght = (encryptedData.Length / 5) * 4 + 4;
                Array.Resize<byte>(ref encryptedData, lenght);
            }
        }

        public void Encrypt(Stream input, Stream output)
        {
            byte[] tmpByteArrData = new byte[bytesNumber];
            byte[] cryptedByteArrData;
            uint[] tmpUintData = new uint[2];
            uint[] cryptedUintData = new uint[2];
            int k = 0;
            int j = 0;
            int p = 0;

            byte[] planeData = new byte[input.Length];
            input.Position = 0;
            input.Read(planeData, 0, (int)input.Length);

            PlaneDataResize(ref planeData);
            cryptedByteArrData = new byte[planeData.Length];

            for (int i = 0; i < planeData.Length; ++i)
            {
                tmpByteArrData[j] = planeData[i];
                if (j == 3)
                {
                    j = 0;
                    tmpUintData[k] = ByteArrToUint(tmpByteArrData);
                    ++k;
                    if (k == 2)
                    {
                        k = 0;

                        GOSTBlockCrypt(tmpUintData, cryptedUintData, key);

                        for (int m = 0; m < cryptedUintData.Length; ++m)
                        {
                            UintToByteArr(p, bytesNumber, cryptedByteArrData, cryptedUintData[m]);
                            p += bytesNumber;
                        }
                    }
                }
                else
                {
                    ++j;
                }
            }

            output.Position = 0;
            output.Write(cryptedByteArrData, 0, cryptedByteArrData.Length);
        }

        public void Decrypt(Stream input, Stream output)
        {
            byte[] tmpByteArrData = new byte[bytesNumber];
            byte[] decryptedByteArrData;
            uint[] tmpUintData = new uint[2];
            uint[] decryptedUintData = new uint[2];
            int k = 0;
            int j = 0;
            int p = 0;

            byte[] encryptedData = new byte[input.Length];
            input.Position = 0;
            input.Read(encryptedData, 0, (int)input.Length);

            EncryptedDataResize(ref encryptedData);
            decryptedByteArrData = new byte[encryptedData.Length];

            for (int i = 0; i < encryptedData.Length; ++i)
            {
                tmpByteArrData[j] = encryptedData[i];
                if (j == 3)
                {
                    j = 0;
                    tmpUintData[k] = ByteArrToUint(tmpByteArrData);
                    ++k;
                    if (k == 2)
                    {
                        k = 0;

                        GOSTBlockDecrypt(tmpUintData, decryptedUintData, key);

                        for (int m = 0; m < decryptedUintData.Length; ++m)
                        {
                            UintToByteArr(p, bytesNumber, decryptedByteArrData, decryptedUintData[m]);
                            p += bytesNumber;
                        }
                    }
                }
                else
                {
                    ++j;
                }
            }

            output.Position = 0;
            output.Write(decryptedByteArrData, 0, decryptedByteArrData.Length);
        }
    }
    /// ГОСТ-28147-89

    /// ElGamal
    public class ElGamal : ICrypto
    {
        private int standardP = 157;
        private int standardG = 3;
        private int standardX = 10;

        static int p;
        static int g;
        static int x;
        static int y;

        public ElGamal()
        {
            SetKey(standardP, standardG, standardX);
        }

        public void SetKey(int newP, int newG, int newX)
        {
            p = newP;
            g = newG;
            x = newX;
            y = Pow(g, x, p);
        }

        int Pow(int a, int b, int m)
        {
            int tmp = a; 
            int sum = tmp; 
            for (int i = 1; i < b; i++)
            {
                for (int j = 1; j < a; j++)
                {
                    sum += tmp;
                    if (sum >= m)
                    {
                        sum -= m;
                    }
                }
                tmp = sum;
            }
            return tmp;
        }

        int Mul(int a, int b, int m)
        {
            int sum = 0;
            for (int i = 0; i < b; i++)
            {
                sum += a;
                if (sum >= m)
                {
                    sum -= m;
                }
            }
            return sum;
        }

        public void Encrypt(Stream input, Stream output)
        {
            Random random = new Random();
            byte byteToCrypt;

            input.Position = 0;
            for (; input.Position < input.Length;)
            {
                byteToCrypt = (byte)input.ReadByte();

                int k = random.Next() % (p - 2) + 1;
                int left = Pow(g, k, p);
                int right = Mul(Pow(y, k, p), byteToCrypt, p);

                output.WriteByte((byte)left);
                output.WriteByte((byte)right);
            }
        }

        public void Decrypt(Stream input, Stream output)
        {
            byte left, right;
            byte[] bytesToDecrypt = new byte[2];

            input.Position = 0;
            for (; input.Position < input.Length; )
            {
                input.Read(bytesToDecrypt, 0, 2);

                left = bytesToDecrypt[0];
                right = bytesToDecrypt[1];

                long m = Mul(right, Pow(left, p - 1 - x, p), p);
                output.WriteByte((byte)m);
            }
        }
    }
    /// ElGamal

    /// MD5
    public interface IHash
    {
        void HashStream(Stream input, Stream output);
    }

    public static class Md5Extensions
    {
        public static uint RotateLeft(this uint val, int count)
        {
            return (val << count) | (val >> (32 - count));
        }

        public static uint RotateRight(this uint val, int count)
        {
            return (val >> count) | (val << (32 - count));
        }

        public static string ConvertToString(this byte[] byteArray)
        {
            return BitConverter.ToString(byteArray).Replace("-", "").ToLower();
        }

        public static byte[] ConvertToByteArray(this string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }
    }

    public class Digest
    {

        #region Variables

        public uint A = 0x67452301;
        public uint B = 0xEFCDAB89;
        public uint C = 0x98BADCFE;
        public uint D = 0X10325476;

        private const uint ChunkSize = 16;

        #endregion

        private uint N(int i)
        {
            uint n = D;

            switch (i)
            {
                case 0:
                    n = A;
                    break;
                case 1:
                    n = B;
                    break;
                case 2:
                    n = C;
                    break;
            }

            return n;
        }

        private void FlipIt(uint hold)
        {
            A = D;
            D = C;
            C = B;
            B = hold;
        }

        public void Process(uint[] buffer)
        {
            uint locA = A;
            uint locB = B;
            uint locC = C;
            uint locD = D;

            for (uint i = 0; i < 64; i++)
            {
                uint range = i / ChunkSize;
                uint p = 0;
                uint index = i;
                switch (range)
                {
                    case 0:
                        p = (B & C) | (~B & D);
                        break;
                    case 1:
                        p = (B & D) | (C & ~D);
                        index = (index * 5 + 1) % ChunkSize;
                        break;
                    case 2:
                        p = B ^ C ^ D;
                        index = (index * 3 + 5) % ChunkSize;
                        break;
                    case 3:
                        p = C ^ (B | ~D);
                        index = (index * 7) % ChunkSize;
                        break;
                }


                FlipIt(B + (A + p + buffer[index] + MD5.T[i]).RotateLeft((int)MD5.Shift[(range * 4) | (i & 3)]));

            }

            A += locA;
            B += locB;
            C += locC;
            D += locD;
        }

        public byte[] GetHash()
        {
            byte[] hash = new byte[16];

            int count = 0;
            for (int i = 0; i < 4; i++)
            {
                uint n = N(i);

                for (int a = 0; a < 4; a++)
                {
                    hash[count++] = (byte)n;
                    n /= (uint)(Math.Pow(2, 8));
                }
            }

            return hash;
        }

    }

    public class Data
    {
        public byte[] DataArr { set; get; }
        public int BlockCount { set; get; }
        public int Size { set; get; }
        public byte[] Padding { set; get; }

        public Data(byte[] data)
        {
            DataArr = data;
            Size = data.Length;
            BlockCount = ((Size + 8) >> 6) + 1;
            int total = BlockCount << 6;

            Padding = new byte[total - Size];
            Padding[0] = 0x80;
            long msg = (Size * 8);
            for (int i = 0; i < 8; i++)
            {
                Padding[Padding.Length - 8 + i] = (byte)msg;
                msg /= 269;
            }
        }

    }

    public class MD5 : IHash
    {

        #region Variables

        public static uint[] Shift = {
        7,12,17,22,
        5,9,14,20,
        4,11,16,23,
        6,10,15,21
        };
        //Определим таблицу констант 64-элементная таблица данных, построенная следующим образом:  T[n]=2^{32}*|sin n|
        //4294967296*sin(i)
        public static uint[] T = {
            0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
            0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
            0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
            0x6b901122,0xfd987193,0xa679438e,0x49b40821,
            0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
            0xd62f105d,0x2441453,0xd8a1e681,0xe7d3fbc8,
            0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
            0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
            0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
            0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
            0x289b7ec6,0xeaa127fa,0xd4ef3085,0x4881d05,
            0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
            0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
            0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
            0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
            0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
        };

        #endregion

        public void HashStream(Stream input, Stream output)
        {
            byte[] buf = new byte[input.Length];
            input.Read(buf, 0, (int)input.Length);

            byte[] result = Process(buf);

            output.Write(result, 0, result.Length);

            if (output.Position != 0)
            {
                output.Position = 0;
            }
        }

        public byte[] Process(byte[] data)
        {
            Data d = new Data(data);

            Digest digest = new Digest();

            uint[] buffer = new uint[16];

            for (int i = 0; i < d.BlockCount; i++)
            {
                int index = i * 64;

                for (int a = 0; a < 64; a++, index++)
                {
                    int bufferIndex = (a / 4);
                    buffer[bufferIndex] = ((uint)((index < d.Size) ? d.DataArr[index] : d.Padding[index - d.Size]) << 24) | (buffer[(bufferIndex)] >> 8);
                }

                digest.Process(buffer);

            }

            return digest.GetHash();

        }
    }
    /// MD5

    /// RSA
    public interface ISign
    {
        void Sign(Stream input, Stream output);
        void SetKey(Stream keyStream);
        void SetHashFunction(IHash hash);
        bool Verify(Stream input);
    }

    public class RSASign : ISign
    {
        IHash hashFunction;
        static BigInteger N;
        static BigInteger d, c;
        static char[] characters = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f' };

        public RSASign()
        {
            SetHashFunction(new MD5());
        }

        public void SetHashFunction(IHash hash)
        {
            hashFunction = hash;
        }

        public void SetKey(Stream key)
        {
            try
            {
                byte[] buf = new byte[key.Length];
                key.Read(buf, 0, buf.Length);
                string[] keys = Encoding.UTF8.GetString(buf).Split(' ');
                N = new BigInteger(Encoding.Default.GetBytes(keys[0]));
                d = new BigInteger(Encoding.Default.GetBytes(keys[1]));
            }
            catch (Exception ex) { }
        }

        public void ProcessRSAParams()
        {
            BigInteger P = GeneratePrime();
            BigInteger Q = GeneratePrime();
            P = 19; Q = 31;
            N = P * Q;
            BigInteger f = (P - 1) * (Q - 1);

            Random rand = new Random();

            while (true)
            {
                d = rand.Next(1, Convert.ToInt32(f.ToString()));
                if (!CheckMutualPrime(Convert.ToInt32(d.ToString()), Convert.ToInt32(f.ToString())))
                {
                    continue;
                }
                break;
            }
            c = Reverse(d, f);
        }

        public void ProcessEuclidean(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y, out BigInteger NOD)
        {
            if (a < b)
            {
                BigInteger temp = a;
                a = b;
                b = temp;
            }

            BigInteger[] U = { a, 1, 0 };
            BigInteger[] V = { b, 0, 1 };
            BigInteger[] T = new BigInteger[3];

            while (V[0] != 0)
            {
                BigInteger q = U[0] / V[0];
                T[0] = U[0] % V[0];
                T[1] = U[1] - q * V[1];
                T[2] = U[2] - q * V[2];
                V.CopyTo(U, 0);
                T.CopyTo(V, 0);
            }

            NOD = U[0];
            x = U[1];
            y = U[2];
        }

        public BigInteger Reverse(BigInteger c, BigInteger m)
        {
            BigInteger x, y, NOD;
            ProcessEuclidean(m, c, out x, out y, out NOD);

            if (y < 0)
            {
                y += m;
            }
            return y;

        }

        public int GeneratePrime()
        {
            Random rand = new Random();
            int a = rand.Next(10000, 11000);

            if (a % 2 == 0)
            {
                a++;
            }
            while (true)
            {
                if (CheckPrime(a))
                {
                    return a;
                }
                a += 2;
            }
        }

        public bool CheckPrime(int n)
        {
            bool isPrime = true;

            for (int i = 2; i < n; i++)
            {
                if (n % i == 0)
                {
                    isPrime = false;
                    break;
                }
            }
            return isPrime;
        }

        public static bool CheckMutualPrime(int a, int b)
        {
            if (a < b)
            {
                int temp = a;
                a = b;
                b = temp;
            }

            while (b != 0)
            {
                int t = a % b;
                a = b;
                b = t;
            }
            return a == 1;
        }

        public void Sign(Stream input, Stream output)
        {
            byte[] buf = new byte[input.Length];

            MemoryStream hash = new MemoryStream();
            hashFunction.HashStream(input, hash);

            buf = new byte[hash.Length];
            hash.Position = 0;
            hash.Read(buf, 0, buf.Length);

            string hash_msg = buf.ConvertToString();

            ProcessRSAParams();

            List<string> result = SignRSA(hash_msg, (int)c, (int)N);

            output.Position = 0;
            output.Write(Encoding.Default.GetBytes(hash_msg), 0, Encoding.Default.GetBytes(hash_msg).Length);
            output.Write(Encoding.Default.GetBytes(" "), 0, Encoding.Default.GetBytes(" ").Length);
            for (int i = 0; i < result.Count; ++i)
            {
                output.Write(Encoding.Default.GetBytes(result[i]), 0, Encoding.Default.GetBytes(result[i]).Length);
                output.Write(Encoding.Default.GetBytes(" "), 0, Encoding.Default.GetBytes(" ").Length);
            }
        }

        private List<string> SignRSA(string s, long e, long n)
        {
            List<string> result = new List<string>();
            BigInteger bi;

            for (int i = 0; i < s.Length; i++)
            {
                int index = Array.IndexOf(characters, s[i]);

                bi = new BigInteger(index);
                bi = BigInteger.Pow(bi, (int)e);

                BigInteger n_ = new BigInteger((int)n);

                bi = bi % n_;

                result.Add(bi.ToString());
            }
            return result;
        }

        private string CheckRSA(List<string> input, long d, long n)
        {
            string result = "";
            BigInteger bi;

            foreach (string item in input)
            {
                bi = new BigInteger(Convert.ToInt32(item));
                bi = BigInteger.Pow(bi, (int)d);

                BigInteger n_ = new BigInteger((int)n);

                bi = bi % n_;

                int index = Convert.ToInt32(bi.ToString());
                result += characters[index].ToString();
            }
            return result;
        }

        public bool Verify(Stream input)
        {
            byte[] buf = new byte[input.Length];
            input.Position = 0;
            input.Read(buf, 0, buf.Length);

            List<string> inp = new List<string>(Encoding.UTF8.GetString(buf).Split(' '));
            List<string> sign = new List<string>(inp.Count - 1);

            for (int i = 0; i < inp.Count - 2; ++i)
            {
                sign.Add(inp[i + 1]);
            }

            return CheckRSA(sign, (int)d, (int)N) == inp[0];
        }
    }
    /// RSA
}