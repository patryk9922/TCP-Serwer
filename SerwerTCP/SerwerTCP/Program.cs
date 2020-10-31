using SerwerTCPBibliotekaKlas;

namespace SerwerTCP
{
    class Program
    {
        static void Main(string[] args)
        {
            SerwerTCPKlasa serwer = new SerwerTCPKlasa("127.0.0.1", 2048);

            serwer.Start();
        }
    }
}
