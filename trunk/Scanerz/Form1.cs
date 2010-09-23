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
using System.Xml;
using System.Xml.Schema;
using System.IO;


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
        int countpackets=0;
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

// добавляем в фаил xml информацию о пакете

        private void XmlAddPacket(String cp, String SourceAddress, String DestinationAddress, String Version, String HeaderLength, String DifferentiatedServices,
            String TotalLength, String Identification, String Flags, String FragmentationOffset, String TTL, String ProtocolType, String Checksum, String Option)
        {
            String Path = string.Format("log{0:yyyyMMddHH}.xml", DateTime.Now);
            try
            {
                XmlDocument XmlDoc = new XmlDocument();
                using (FileStream fStream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    XmlDoc.Load(fStream);
                    fStream.Close();
                }
                
                //XmlAttribute newatrr;
                XmlElement newitem2=XmlDoc.CreateElement("Пакеты");
                XmlElement newitem;

                newitem = XmlDoc.CreateElement("Пакет");

                newitem.SetAttribute("НомерПакета", cp);
                newitem.SetAttribute("Откуда", SourceAddress);
                newitem.SetAttribute("Куда", DestinationAddress);
                newitem.SetAttribute("Версия", Version);
                newitem.SetAttribute("Длина", HeaderLength);
                newitem.SetAttribute("Сервисы", DifferentiatedServices);
                newitem.SetAttribute("ОбщаяДлина", TotalLength);
                newitem.SetAttribute("Идентификатор", Identification);
                newitem.SetAttribute("Флаги", Flags);
                newitem.SetAttribute("Смещение", FragmentationOffset);
                newitem.SetAttribute("ТТЛ", TTL);
                newitem.SetAttribute("ТипПротокола", ProtocolType);
                newitem.SetAttribute("КонтрольнаяСумма", Checksum);
                newitem.SetAttribute("Опция", Option);     

                newitem2.AppendChild(newitem);
                XmlDoc.DocumentElement.InsertAfter(newitem2, XmlDoc.DocumentElement.LastChild);
                FileStream writer = new FileStream(Path, FileMode.Truncate, FileAccess.Write, FileShare.ReadWrite);
                XmlDoc.Save(writer);
                writer.Close();
            }
            catch(Exception ex) 
            {
                MessageBox.Show(ex.ToString(), "sabakas", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }


 // считываем из xml фаила и выводим в грид

        private void AddPacketToGrid()
        {
            String Path = string.Format("log{0:yyyyMMddHH}.xml", DateTime.Now);
            dgvPackets.Rows.Clear();
            XmlTextReader reader = null;

            try
            {
                reader = new XmlTextReader(Path);
                reader.WhitespaceHandling = WhitespaceHandling.None;	// пропускаем пустые узлы
                while (reader.Read())
                    if (reader.NodeType == XmlNodeType.Element)
                        if (reader.Name == "Пакет" && reader.AttributeCount != 0)
                        {
                            String cp = reader.GetAttribute("НомерПакета");
                            String SourceAddress = reader.GetAttribute("Откуда");
                            String DestinationAddress = reader.GetAttribute("Куда");
                            String Version = reader.GetAttribute("Версия");
                            String HeaderLength = reader.GetAttribute("Длина");
                            String DifferentiatedServices = reader.GetAttribute("Сервисы");
                            String TotalLength = reader.GetAttribute("ОбщаяДлина");
                            String Identification = reader.GetAttribute("Идентификатор");
                            String Flags = reader.GetAttribute("Флаги");
                            String FragmentationOffset = reader.GetAttribute("Смещение");
                            String TTL = reader.GetAttribute("ТТЛ");
                            String ProtocolType = reader.GetAttribute("ТипПротокола");
                            String Checksum = reader.GetAttribute("КонтрольнаяСумма");
                            String Option = reader.GetAttribute("Опция");                      
                            dgvPackets.Rows.Insert(0 ,cp, SourceAddress, DestinationAddress, Version, HeaderLength, DifferentiatedServices, TotalLength,
                            Identification, Flags, FragmentationOffset, TTL, ProtocolType, Checksum, Option);
                        }


            }
            catch (Exception ex)
            {
                MessageBox.Show("Ошибка: " + ex.Message);
            }
            finally
            {
                if (reader != null)
                    reader.Close();
            }

        }


//  заполняем данные в  главном гриде

        private void OnAddRowIP(byte[] byteData, int nReceived)
        {
            IPHeader ipHeader = new IPHeader(byteData, nReceived);
            countpackets++;
    //        dgvPackets.Rows.Add(countpackets, ipHeader.SourceAddress.ToString(), ipHeader.DestinationAddress.ToString(), 
    //          ipHeader.Version, ipHeader.HeaderLength, ipHeader.DifferentiatedServices, ipHeader.TotalLength, ipHeader.Identification,
    //ipHeader.Flags, ipHeader.FragmentationOffset, ipHeader.TTL, ipHeader.ProtocolType, ipHeader.Checksum, "");

            XmlAddPacket(countpackets.ToString(), ipHeader.SourceAddress.ToString(), ipHeader.DestinationAddress.ToString(),
              ipHeader.Version, ipHeader.HeaderLength, ipHeader.DifferentiatedServices, ipHeader.TotalLength, ipHeader.Identification,
    ipHeader.Flags, ipHeader.FragmentationOffset, ipHeader.TTL, ipHeader.ProtocolType.ToString(), ipHeader.Checksum, "");

            AddPacketToGrid();
        }

 
// Конвертируем массив байтов в строку        
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

                Dump(tcpHeader.Data, Convert.ToInt32(tcpHeader.HeaderLength));

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


   // Вывод дампа
        public void Dump(byte[] bytes , int len)
        {
            
            this.dgvDump.Rows.Clear();
            len *= 4;
            try{
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
                        ((char)a[0]).ToString() + ((char)a[1]).ToString() + ((char)a[2]).ToString() + ((char)a[3]).ToString() + ((char)a[4]).ToString()
                        + ((char)a[5]).ToString() + ((char)a[6]).ToString() + ((char)a[7]).ToString() + ((char)a[8]).ToString() + ((char)a[9]).ToString()
                        + ((char)a[10]).ToString() + ((char)a[11]).ToString() + ((char)a[12]).ToString() + ((char)a[13]).ToString() + ((char)a[14]).ToString());
                }

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString(), "sabakas", MessageBoxButtons.OK, MessageBoxIcon.Error);
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

                    //Создаем XML фаил , лог пакетов

                    XmlTextWriter writer = null;
                    try
                    {
                        String Path = string.Format("log{0:yyyyMMddHH}.xml", DateTime.Now);
                        writer = new XmlTextWriter(Path, System.Text.Encoding.Unicode);

                        writer.WriteStartDocument();
                        writer.WriteStartElement("Старт");

                            writer.WriteStartElement("Начало");
                            writer.WriteAttributeString("ДатаСтарта", DateTime.Now.ToString());
                            writer.WriteEndElement();
                        
                        writer.WriteEndElement();
                        writer.WriteEndDocument();
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Ошибка: " + ex.Message);
                    }
                    finally
                    {
                        if (writer != null)
                            writer.Close();
                    }
                                         
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

        private void dgvPackets_ColumnAdded(object sender, DataGridViewColumnEventArgs e)
        {

        }

        private void dgvPackets_SortCompare(object sender, DataGridViewSortCompareEventArgs e)
        {

        }
    }
}
