using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using CryptoLibrary;
using System.IO;

namespace CryptoProgram
{
    public partial class Form1 : Form
    {
        private string source;

        private string[] outputTable = { "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010", "1011", "1100", "1101", "1110", "1111" };

        public Form1()
        {
            InitializeComponent();
            radioButton1.Checked = true;
        }

        private string getHexOutputText(byte[] buffer)
        {
            string output = "";

            for (int i = 0; i < buffer.Length; i++)
            {
                string buf = "";
                byte temp = buffer[i];
                for (int k = 0; k < 8; k++)
                {
                    buf += ((temp & (1 << k)) != 0) ? "1" : "0";
                }

                string left = "", right = "";
                for (int k = 0; k < 4; k++)
                {
                    right += buf[k];
                    left += buf[k + 4];
                }
                int indexLeft = Array.IndexOf(outputTable, left);
                string outputLeft = Convert.ToString(indexLeft, 16);
                int indexRight = Array.IndexOf(outputTable, right);
                string outputRight = Convert.ToString(indexRight, 16);

                output += outputLeft + outputRight + " ";
            }
            return output;
        }

        private void GOST()
        {
            MemoryStream sourceDataStream = new MemoryStream(Encoding.Default.GetBytes(source));
            MemoryStream encryptedDataStream = new MemoryStream();
            MemoryStream decryptedDataStream = new MemoryStream();

            GOST28147_89 gost = new GOST28147_89();
            gost.Encrypt(sourceDataStream, encryptedDataStream);
            gost.Decrypt(encryptedDataStream, decryptedDataStream);

            textBox2.Text = getHexOutputText(encryptedDataStream.ToArray());
            textBox3.Text = Encoding.Default.GetString(decryptedDataStream.ToArray()).TrimEnd('\0');
        }

        private void ElGamal()
        {
            ElGamal elGamal = new ElGamal();

            MemoryStream sourceDataStream = new MemoryStream(Encoding.Default.GetBytes(source));
            MemoryStream encryptedDataStream = new MemoryStream();
            MemoryStream decryptedDataStream = new MemoryStream();

            elGamal.Encrypt(sourceDataStream, encryptedDataStream);
            elGamal.Decrypt(encryptedDataStream, decryptedDataStream);

            textBox2.Text = getHexOutputText(encryptedDataStream.ToArray());
            textBox3.Text = Encoding.Default.GetString(decryptedDataStream.ToArray()).TrimEnd('\0');
        }

        private void MD5()
        {
            MemoryStream sourceStream = new MemoryStream(source.ConvertToByteArray());
            MemoryStream hashedStream = new MemoryStream();

            MD5 md5 = new MD5();

            md5.HashStream(sourceStream, hashedStream);

            textBox2.Text = getHexOutputText(hashedStream.ToArray());
        }

        private void RSA()
        {
            MemoryStream input = new MemoryStream(Encoding.Default.GetBytes(source));
            MemoryStream output = new MemoryStream();

            RSASign rsa = new RSASign();
            rsa.Sign(input, output);

            textBox2.Text = getHexOutputText(input.ToArray());

            if (rsa.Verify(output))
            {
                textBox3.Text = "Подпись верна";
            }
            else
            {
                textBox3.Text = "Подпись не верна";
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            source = textBox1.Text;

            if (radioButton1.Checked)
            {
                GOST();
            }

            if (radioButton2.Checked)
            {
                ElGamal();
            }

            if (radioButton3.Checked)
            {
                MD5();
            }

            if (radioButton4.Checked)
            {
                RSA();
            }
        }

        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {
            textBox2.Text = "";
            textBox3.Text = "";

            if (radioButton1.Checked)
            {
                button1.Text = "Зашифровать";
                label2.Text = "Зашифрованный текст";
                label3.Text = "Расшифрованный текст";
                label3.Visible = true;
                textBox3.Visible = true;
            }
        }

        private void radioButton2_CheckedChanged(object sender, EventArgs e)
        {
            textBox2.Text = "";
            textBox3.Text = "";

            if (radioButton2.Checked)
            {
                button1.Text = "Зашифровать";
                label2.Text = "Зашифрованный текст";
                label3.Text = "Расшифрованный текст";
                label3.Visible = true;
                textBox3.Visible = true;
            }
        }

        private void radioButton3_CheckedChanged(object sender, EventArgs e)
        {
            textBox2.Text = "";
            textBox3.Text = "";

            if (radioButton3.Checked)
            {
                button1.Text = "Получить хэш";
                label2.Text = "Хэш";
                label3.Visible = false;
                textBox3.Visible = false;
            }
        }

        private void radioButton4_CheckedChanged(object sender, EventArgs e)
        {
            textBox2.Text = "";
            textBox3.Text = "";

            if (radioButton4.Checked)
            {
                button1.Text = "Подписать";
                label2.Text = "Подпись";
                label3.Text = "Результат подписи";
                label3.Visible = true;
                textBox3.Visible = true;
            }
        }
    }
}
