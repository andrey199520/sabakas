using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;


namespace Scanerz
{
   
    public enum Protocol
    {
        TCP = 6,
        UDP = 17,
        Unknown = -1
    };

    public partial class scanerz : Form
    {
        int countpackets = 0;
        private Socket mainSocket;                          //сокет который захватывает все входящие пакеты
        private byte[] byteData = new byte[4096];
   
        private delegate void AddRowIP(byte[] byteData, int nReceived);
        private delegate void AddRowTCPProtocol(TCPHeader TCPHeader);
        private delegate void AddRowUDPProtocol(UDPHeader udpHeader);
        private delegate void AddRowDNSProtocol(byte[] byteData, int nLength);

        public scanerz()
        {
            InitializeComponent();
        }
        //------------------------------------------------------------------------------------------------------------------

        private void OnReceive(IAsyncResult ar)
        {
            try
            {
                int nReceived = mainSocket.EndReceive(ar);
                //анализ байтов приема...
                ParseData(byteData, nReceived);
                byteData = new byte[4096];
                //другой  вызов  BeginReceive так чтобы мы продожили получать входящие пакеты               
                mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,new AsyncCallback(OnReceive), null);            
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "sabakas", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        // ПАРСИМ
        private void ParseData(byte[] byteData, int nReceived)
        {        
            IPHeader ipHeader = new IPHeader(byteData, nReceived);
            AddRowIP AddRowIP2 = new AddRowIP(OnAddRowIP);
            dgvPackets.Invoke(AddRowIP2, new object[] {byteData, nReceived });

            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:

                    TCPHeader tcpHeader = new TCPHeader(ipHeader.Data, ipHeader.MessageLength);
                    AddRowTCPProtocol RowTCPProtocol = new AddRowTCPProtocol(MakeTCP);
                    dgvParamProt.Invoke(RowTCPProtocol, new object[] { tcpHeader });
                  if (tcpHeader.DestinationPort == "53" || tcpHeader.SourcePort == "53")
                    {
                        AddRowDNSProtocol RowDNSProtocol = new AddRowDNSProtocol(MakeDNS);
                        dgvParamProt.Invoke(RowDNSProtocol, new object[] { tcpHeader.Data, (int)tcpHeader.MessageLength });      
                    }

                    break;

                case Protocol.UDP:

                    UDPHeader udpHeader = new UDPHeader(ipHeader.Data,              //IPHeader.Data stores the data being 
                        //carried by the IP datagram
                                                       (int)ipHeader.MessageLength);//Length of the data field                    

                    AddRowUDPProtocol RowUDPProtocol = new AddRowUDPProtocol(MakeUDP);
                    dgvParamProt.Invoke(RowUDPProtocol, new object[] { udpHeader });

                
                    //If the port is equal to 53 then the underlying protocol is DNS
                    //Note: DNS can use either TCP or UDP thats why the check is done twice
                   if (udpHeader.DestinationPort == "53" || udpHeader.SourcePort == "53")
                   {
                       AddRowDNSProtocol RowDNSProtocol = new AddRowDNSProtocol(MakeDNS);
                       dgvParamProt.Invoke(RowDNSProtocol, new object[] { udpHeader.Data, Convert.ToInt32(udpHeader.Length) - 8 });
                    }

                    break;

                case Protocol.Unknown:
                    break;
            }

        }


        private void OnAddRowIP(byte[] byteData, int nReceived)
        {
            IPHeader ipHeader = new IPHeader(byteData, nReceived);
            countpackets++;
            dgvPackets.Rows.Add(countpackets, ipHeader.SourceAddress.ToString(), ipHeader.DestinationAddress.ToString(), ipHeader.Version, ipHeader.HeaderLength, ipHeader.DifferentiatedServices, ipHeader.TotalLength, ipHeader.Identification,
    ipHeader.Flags, ipHeader.FragmentationOffset, ipHeader.TTL, ipHeader.ProtocolType, ipHeader.Checksum, "");
        }

        private static string ConvertToString(byte[] bytes)
        {
            string s = @"";
            foreach (byte b in bytes)
            {
                string r = b.ToString();
                s += r;
            }
            return s;
        }

        //Helper function which returns the information contained in the TCP header as a
        //tree node
        private void MakeTCP(TCPHeader tcpHeader){

            this.dgvParamProt.Rows.Clear();
            this.dgvParamProt.Columns.Clear();

            DataGridViewTextBoxColumn col0 = new DataGridViewTextBoxColumn();
            col0.HeaderText = "Описание";
            col0.Name = "ID";
            DataGridViewTextBoxColumn col1 = new DataGridViewTextBoxColumn();
            col1.HeaderText = "Значение";
            col1.Name = "ID1";

            this.dgvParamProt.Columns.Add(col0);
            this.dgvParamProt.Columns.Add(col1);              
              
                 
                this.dgvParamProt.Rows.Add("Source Port:", tcpHeader.SourcePort);
                this.dgvParamProt.Rows.Add("Destination Port:", tcpHeader.DestinationPort);
                this.dgvParamProt.Rows.Add("Sequence Number: ", tcpHeader.SequenceNumber);
                if (tcpHeader.AcknowledgementNumber != "")
                {
                    this.dgvParamProt.Rows.Add("Acknowledgement Number: ", tcpHeader.AcknowledgementNumber);
                }
                this.dgvParamProt.Rows.Add("Header Length:", tcpHeader.HeaderLength);
                this.dgvParamProt.Rows.Add("Flags:", tcpHeader.Flags);
                this.dgvParamProt.Rows.Add("Window Size:", tcpHeader.WindowSize);
                this.dgvParamProt.Rows.Add("Checksum:", tcpHeader.Checksum);
                if (tcpHeader.UrgentPointer != "")
                {
                    this.dgvParamProt.Rows.Add("Urgent Pointer:", tcpHeader.UrgentPointer);
                }

                Dump(tcpHeader.Data, Convert.ToInt32(tcpHeader.MessageLength));

        }


        //Helper function which returns the information contained in the UDP header as a
        //tree node
        private void MakeUDP(UDPHeader udpHeader)
        {
            this.dgvParamProt.Rows.Clear();
            this.dgvParamProt.Columns.Clear();

            DataGridViewTextBoxColumn col0 = new DataGridViewTextBoxColumn();
            col0.HeaderText = "Описание";
            col0.Name = "ID";
            DataGridViewTextBoxColumn col1 = new DataGridViewTextBoxColumn();
            col1.HeaderText = "Значение";
            col1.Name = "ID1";

            this.dgvParamProt.Columns.Add(col0);
            this.dgvParamProt.Columns.Add(col1);

            dgvParamProt.Rows.Add("Source Port:", udpHeader.SourcePort);
            dgvParamProt.Rows.Add("Destination Port:", udpHeader.DestinationPort);
            dgvParamProt.Rows.Add("Length:", udpHeader.Length);
            dgvParamProt.Rows.Add("Checksum:", udpHeader.Checksum);
            dgvParamProt.Rows.Add("Date:", ConvertToString(udpHeader.Data));

            Dump(udpHeader.Data, Convert.ToInt32(udpHeader.Length));

        }


        //Helper function which returns the information contained in the DNS header as a
        //tree node
        public void MakeDNS(byte[] byteData, int nLength)
        {
            DNSHeader dnsHeader = new DNSHeader(byteData, nLength);
            this.dgvParamProt.Rows.Clear();
            this.dgvParamProt.Columns.Clear();

            DataGridViewTextBoxColumn col0 = new DataGridViewTextBoxColumn();
            col0.HeaderText = "Описание";
            col0.Name = "ID";
            DataGridViewTextBoxColumn col1 = new DataGridViewTextBoxColumn();
            col1.HeaderText = "Значение";
            col1.Name = "ID1";

            this.dgvParamProt.Columns.Add(col0);
            this.dgvParamProt.Columns.Add(col1);

            dgvParamProt.Rows.Add("Identification:", dnsHeader.Identification);
            dgvParamProt.Rows.Add("Flags:", dnsHeader.Flags);
            dgvParamProt.Rows.Add("Questions:", dnsHeader.TotalQuestions);
            dgvParamProt.Rows.Add("Answer RRs: ", dnsHeader.TotalAnswerRRs);
            dgvParamProt.Rows.Add("Authority RRs:", dnsHeader.TotalAuthorityRRs);
            dgvParamProt.Rows.Add("Additional RRs:", dnsHeader.TotalAdditionalRRs);

        }


   // вывод дампа
        public void Dump(byte[] bytes , int len)
        {
            
            this.dgvDump.Rows.Clear();
            len *= 4;
            try
            {
                byte[] a = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                for (int i = 0; i < len / 15; i++)
                {
                    for (int j = 0; j < 15; j++)
                    {

                        a[j] = bytes[(i + 1) * j];

                    }
                    dgvDump.Rows.Add(i.ToString("X2"), a[0].ToString("X2"), a[1].ToString("X2"), a[2].ToString("X2"), a[3].ToString("X2"), a[4].ToString("X2"),
                        a[5].ToString("X2"), a[6].ToString("X2"), a[7].ToString("X2"), a[8].ToString("X2"),
                        a[9].ToString("X2"), a[10].ToString("X2"), a[11].ToString("X2"), a[12].ToString("X2"), a[13].ToString("X2"), a[14].ToString("X2"),
                        a[0].ToString() + a[1].ToString() + a[2].ToString() + a[3].ToString() + a[4].ToString() +
                        a[5].ToString() + a[6].ToString() + a[7].ToString() + a[8].ToString() + a[10].ToString() +
                        a[11].ToString() + a[12].ToString() + a[13].ToString() + a[14].ToString());
                }

            }
            catch (Exception ex)
            {
                MessageBox.Show("Чето не хочу работать с дампом!", "sabakas", MessageBoxButtons.OK, MessageBoxIcon.Error);
            } 
            

        }

        //-----------------------------------------------------------------------------------------------------------------------

        private void toolStripButton3_Click(object sender, EventArgs e)
        {
            try
            {
                    //Для анализа сокета захватывает пакеты может иметь raw сокет , с
                    //создаем сокет
                    //Инициализирует новый экземпляр класса Socket, используя заданное семейство адресов, тип сокета и протокол.
                    //Socket(AddressFamily, SocketType, ProtocolType)

                    mainSocket = new Socket(AddressFamily.InterNetwork,SocketType.Raw, ProtocolType.IP);

                    //биндим сокет на выбранный интерфейс
                    mainSocket.Bind(new IPEndPoint(IPAddress.Parse(tscmbInterface.Text), 0));

                    //Устанавливаем опции сокета
                    mainSocket.SetSocketOption(SocketOptionLevel.IP,            //принимать только ip пакеты
                                               SocketOptionName.HeaderIncluded, //установить включение хидера
                                               true);                           //опция

                    byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                    byte[] byOut = new byte[4] { 1, 0, 0, 0 }; //захватить выходящий пакет

                    //Socket.IOControl аналог WSAIoctl метод Winsock 2
                    mainSocket.IOControl(IOControlCode.ReceiveAll,              //эквивалент констант SIO_RCVALL 
                        //Winsock 2
                                         byTrue,
                                         byOut);

                    //Старт прием пакетов асинхроннно. Начинает выполнение асинхронного приема данных с подключенного объекта Socket.
                    mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None, new AsyncCallback(OnReceive), null);
                                         
            }


            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "sabakas", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }


        //загрузка формы.
        // проверяем интерфесы. какие существуют на ПК
        private void scanerz_Load(object sender, EventArgs e)
        {
            string strIP = null;
            IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));
            if (HosyEntry.AddressList.Length > 0)
            {
                foreach (IPAddress ip in HosyEntry.AddressList)
                {
                    strIP = ip.ToString();
                    tscmbInterface.Items.Add(strIP);
                }
            }    

        }

       // Останавливаем сканирование
        private void toolStripButton4_Click(object sender, EventArgs e)
        {
            try
            {
                mainSocket.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Он и не сканировал, балван!", "Sabakas", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void очиститьВсеToolStripMenuItem_Click(object sender, EventArgs e)
        {           
            this.dgvParamProt.Rows.Clear();
            this.dgvPackets.Rows.Clear();
            this.dgvDump.Rows.Clear();
        }
    }
}
