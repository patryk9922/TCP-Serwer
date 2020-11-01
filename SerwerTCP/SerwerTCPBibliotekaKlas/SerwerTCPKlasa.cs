using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;

namespace SerwerTCPBibliotekaKlas
{
    public class SerwerTCPKlasa
    {
        TcpListener tcpListener;
        IPAddress ipAddress;
        int port;

        public delegate void TransmissionDelegate(NetworkStream stream);

        private static readonly Encoding encoding = new ASCIIEncoding();

        byte[] key = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
        byte[] iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

        Aes aes;

        public SerwerTCPKlasa(string _ip, int _port)
        {
            ipAddress = IPAddress.Parse(_ip);
            port = _port;
            aes = Aes.Create();
        }

        public void Start()
        {
            tcpListener = new TcpListener(ipAddress, port);
            tcpListener.Start();

            while(true)
            {
                TcpClient tcpClient = tcpListener.AcceptTcpClient();
                NetworkStream stream = tcpClient.GetStream();
                TransmissionDelegate transmissionDelegate = new TransmissionDelegate(ObsluzKlienta);
                transmissionDelegate.BeginInvoke(stream, TransmissionCallback, tcpClient);
            }
        }

        private void TransmissionCallback(IAsyncResult asyncResult)
        {
            TcpClient klient = (TcpClient)asyncResult.AsyncState;

            klient.Close();
        }

        private void ObsluzKlienta(NetworkStream stream)
        {
            string dane;

            while (true)
            {
                try
                {
                    WyslijWiadomosc(stream, "Podaj login: ");

                    dane = OdbierzWiadomosc(stream);

                    WyslijWiadomosc(stream, "Podaj haslo: ");

                    dane = dane + ";" + OdbierzWiadomosc(stream) + "|";

                    if (SprawdzDane(dane))
                    {
                        dane = dane.Substring(0, dane.IndexOf(";"));
                        Zaloguj(stream, dane);

                        ObsluzKomendy(stream, dane);
                    }
                    else
                    {
                        Rejestracja(stream, dane);
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    break;
                }
            }
        }

        private void WyslijWiadomosc(NetworkStream stream, string wiadomosc)
        {
            int ilosc = wiadomosc.Length;
            byte[] bufor = new byte[ilosc];

            for (int i = 0; i < ilosc; i++)
            {
                bufor[i] = (byte)wiadomosc[i];
            }

            stream.Write(bufor, 0, ilosc);
        }

        private string OdbierzWiadomosc(NetworkStream stream)
        {
            byte[] bufor = new byte[1024];

            int ilosc = stream.Read(bufor, 0, 1024);
            string wiadomosc = encoding.GetString(bufor, 0, ilosc);
            stream.Read(bufor, 0, 2);

            return wiadomosc;
        }

        private void Zaloguj(NetworkStream stream, string dane)
        {
            string wiadomosc = "Witaj " + dane + "\r\n";
            int ilosc = wiadomosc.Length;
            byte[] bufor = new byte[ilosc];

            for (int i = 0; i < ilosc; i++)
            {
                bufor[i] = (byte)wiadomosc[i];
            }

            stream.Write(bufor, 0, ilosc);
        }

        private void ObsluzKomendy(NetworkStream stream, string dane)
        {
            while (true)
            {
                string wiadomosc = dane + ": ";
                int ilosc = wiadomosc.Length;
                byte[] bufor = new byte[1024];

                for (int i = 0; i < ilosc; i++)
                {
                    bufor[i] = (byte)wiadomosc[i];
                }
                stream.Write(bufor, 0, ilosc);

                ilosc = stream.Read(bufor, 0, 1024);
                wiadomosc = encoding.GetString(bufor, 0, ilosc);
                stream.Read(bufor, 0, 2);

                wiadomosc = "Echo: " + wiadomosc + "\r\n";
                ilosc = wiadomosc.Length;
                for (int i = 0; i < ilosc; i++)
                {
                    bufor[i] = (byte)wiadomosc[i];
                }
                stream.Write(bufor, 0, ilosc);
            }
        }

        private void Rejestracja(NetworkStream stream, string dane)
        {
            string wiadomosc = "Nie znaleziono takiego konta\r\n";
            int ilosc = wiadomosc.Length;
            byte[] bufor = new byte[1024];

            for (int i = 0; i < ilosc; i++)
            {
                bufor[i] = (byte)wiadomosc[i];
            }

            stream.Write(bufor, 0, ilosc);

            wiadomosc = "Chcesz sie zarejestrowac? (Tak/Nie) ";
            ilosc = wiadomosc.Length;

            for (int i = 0; i < ilosc; i++)
            {
                bufor[i] = (byte)wiadomosc[i];
            }

            stream.Write(bufor, 0, ilosc);

            ilosc = stream.Read(bufor, 0, 1024);
            wiadomosc = encoding.GetString(bufor, 0, ilosc);
            stream.Read(bufor, 0, 2);

            if (wiadomosc == "Tak" || wiadomosc == "tak")
            {
                Zarejestruj(dane);
                wiadomosc = "Zarejestrowano pomyslnie. Zaloguj sie ponownie\r\n";
                ilosc = wiadomosc.Length;

                for (int i = 0; i < ilosc; i++)
                {
                    bufor[i] = (byte)wiadomosc[i];
                }

                stream.Write(bufor, 0, ilosc);
            }
        }

        private bool SprawdzDane(string dane)
        {
            try
            {
                FileStream fileStream = new FileStream("NotPasswords.bin", FileMode.OpenOrCreate);
                CryptoStream cryptoStream = new CryptoStream(fileStream, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read);
                StreamReader streamReader = new StreamReader(cryptoStream);
                string data;
                dane = dane.Substring(0, dane.Length - 1);

                try
                {
                    data = streamReader.ReadToEnd();

                    foreach(var linia in data.Split('|'))
                    {
                        if (linia == dane)
                        {
                            return true;
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
                finally
                {
                    streamReader.Close();
                    cryptoStream.Close();
                    fileStream.Close();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message); 
            }

            return false;
        }

        private void Zarejestruj(string dane)
        {
            try
            {
                FileStream fileStream = new FileStream("NotPasswords.bin", FileMode.OpenOrCreate);
                CryptoStream cryptoStream = new CryptoStream(fileStream, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read);
                StreamReader streamReader = new StreamReader(cryptoStream);
                string data;
                data = streamReader.ReadToEnd();
                streamReader.Close();
                cryptoStream.Close();
                fileStream.Close();

                dane = data + dane;

                FileStream fileStream2 = new FileStream("NotPasswords.bin", FileMode.OpenOrCreate);
                CryptoStream cryptoStream2 = new CryptoStream(fileStream2, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write);

                byte[] daneB = new byte[dane.Length];

                for(int i = 0; i < dane.Length; i++)
                {
                    daneB[i] = (byte)dane[i];
                }

                cryptoStream2.Write(daneB, 0, dane.Length);
                cryptoStream2.Close();
                fileStream2.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }
}
