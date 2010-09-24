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
        
//Принимаем данные и обрабатываем
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


// Парсим полученный массив байтов в читабельный вид 
        private void ParseData(byte[] byteData, int nReceived)
        {        
            IPHeader ipHeader = new IPHeader(byteData, nReceived);
            AddRowIP AddRowIP2 = new AddRowIP(OnAddRowIP);
            dgvPackets.Invoke(AddRowIP2, new object[] {byteData, nReceived });

            //switch (ipHeader.ProtocolType)
            //{
            //    case Protocol.TCP:

            //        TCPHeader tcpHeader = new TCPHeader(ipHeader.Data, ipHeader.MessageLength);
            //        AddRowTCPProtocol RowTCPProtocol = new AddRowTCPProtocol(MakeTCP);
            //        dgvParamProt.Invoke(RowTCPProtocol, new object[] { tcpHeader });
            //      if (tcpHeader.DestinationPort == "53" || tcpHeader.SourcePort == "53")
            //        {
            //            AddRowDNSProtocol RowDNSProtocol = new AddRowDNSProtocol(MakeDNS);
            //            dgvParamProt.Invoke(RowDNSProtocol, new object[] { tcpHeader.Data, (int)tcpHeader.MessageLength });      
            //        }

            //        break;

            //    case Protocol.UDP:

            //        UDPHeader udpHeader = new UDPHeader(ipHeader.Data,              //IPHeader.Data stores the data being 
            //            //carried by the IP datagram
            //                                           (int)ipHeader.MessageLength);//Length of the data field                    

            //        AddRowUDPProtocol RowUDPProtocol = new AddRowUDPProtocol(MakeUDP);
            //        dgvParamProt.Invoke(RowUDPProtocol, new object[] { udpHeader });

                
            //        //If the port is equal to 53 then the underlying protocol is DNS
            //        //Note: DNS can use either TCP or UDP thats why the check is done twice
            //       if (udpHeader.DestinationPort == "53" || udpHeader.SourcePort == "53")
            //       {
            //           AddRowDNSProtocol RowDNSProtocol = new AddRowDNSProtocol(MakeDNS);
            //           dgvParamProt.Invoke(RowDNSProtocol, new object[] { udpHeader.Data, Convert.ToInt32(udpHeader.Length) - 8 });
            //        }

            //        break;

            //    case Protocol.Unknown:
            //        break;
            //}

        }


// добавляем в фаил xml информацию о пакете с udp протоколом

        private void XmlAddPacket(String cp, String SourceAddress, String DestinationAddress, String Version, String HeaderLength, String DifferentiatedServices,
            String TotalLength, String Identification, String Flags, String FragmentationOffset, String TTL, String ProtocolType, String Checksum, String Option,
            String SourcePort, String DestinationPort, String Length, String udpChecksum, byte[] Data)
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
                XmlElement newitem2 = XmlDoc.CreateElement("Пакеты");
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
                newitem.SetAttribute("ПортИсточника", SourcePort);
                newitem.SetAttribute("ПортПриемника", DestinationPort);
                newitem.SetAttribute("ДлинаПротокола", Length);
                newitem.SetAttribute("ПроверочнаяСуммаПротокола", udpChecksum);
                newitem.SetAttribute("СодержимоеПакета", ConvertToString(Data));

                newitem2.AppendChild(newitem);
                XmlDoc.DocumentElement.InsertAfter(newitem2, XmlDoc.DocumentElement.LastChild);
                FileStream writer = new FileStream(Path, FileMode.Truncate, FileAccess.Write, FileShare.ReadWrite);
                XmlDoc.Save(writer);
                writer.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString(), "sabakas", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }



// добавляем в фаил xml информацию о пакете с TCP протоколом

        private void XmlAddPacket(String cp, String SourceAddress, String DestinationAddress, String Version, String HeaderLength, String DifferentiatedServices,
            String TotalLength, String Identification, String Flags, String FragmentationOffset, String TTL, String ProtocolType, String Checksum, String Option,
            String SourcePort, String DestinationPort, String SequenceNumber, String AcknowledgementNumber,String tcpHeaderLength, String tcpFlags,
            String WindowSize, String tcpChecksum, String UrgentPointer, byte[] Data)
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
                newitem.SetAttribute("ПортИсточника", SourcePort);
                newitem.SetAttribute("ПортПриемника", DestinationPort);
                newitem.SetAttribute("ПорядковыйНомер", SequenceNumber);
                newitem.SetAttribute("ПодтверждениеКоличества", AcknowledgementNumber);
                newitem.SetAttribute("ДлинаЗаголовка", tcpHeaderLength);
                newitem.SetAttribute("ФлагиПротокола", tcpFlags);
                newitem.SetAttribute("РазмерОкна", WindowSize);
                newitem.SetAttribute("ПроверочнаяСуммаПротокола", tcpChecksum);
                newitem.SetAttribute("УказательСрочности", UrgentPointer);
                newitem.SetAttribute("СодержимоеПакета", ConvertToString(Data));  

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


 // считываем из xml фаила и выводим в главный грид

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


//  заполняем данные в  грид и в XML фаиле

        private void OnAddRowIP(byte[] byteData, int nReceived)
        {
            IPHeader ipHeader = new IPHeader(byteData, nReceived);
            countpackets++;

            // выбираем правило записи

            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:

                    TCPHeader tcpHeader = new TCPHeader(ipHeader.Data, ipHeader.MessageLength);

                    // считываем из потока данные в xml
                    XmlAddPacket(countpackets.ToString(), ipHeader.SourceAddress.ToString(), ipHeader.DestinationAddress.ToString(),
                                 ipHeader.Version, ipHeader.HeaderLength, ipHeader.DifferentiatedServices, ipHeader.TotalLength, ipHeader.Identification,
                                 ipHeader.Flags, ipHeader.FragmentationOffset, ipHeader.TTL, ipHeader.ProtocolType.ToString(), ipHeader.Checksum, "",
                                 tcpHeader.SourcePort, tcpHeader.DestinationPort, tcpHeader.SequenceNumber, tcpHeader.AcknowledgementNumber,
                                 tcpHeader.HeaderLength, tcpHeader.Flags, tcpHeader.WindowSize, tcpHeader.Checksum, tcpHeader.UrgentPointer,
                                 tcpHeader.Data);

                    if (tcpHeader.DestinationPort == "53" || tcpHeader.SourcePort == "53")
                    {
                    //    AddRowDNSProtocol RowDNSProtocol = new AddRowDNSProtocol(MakeDNS);
                    //    dgvParamProt.Invoke(RowDNSProtocol, new object[] { tcpHeader.Data, (int)tcpHeader.MessageLength });
                    }

                    break;

                case Protocol.UDP:

                    UDPHeader udpHeader = new UDPHeader(ipHeader.Data,(int)ipHeader.MessageLength);                

                    // считываем из потока данные в xml
                    XmlAddPacket(countpackets.ToString(), ipHeader.SourceAddress.ToString(), ipHeader.DestinationAddress.ToString(),
                                 ipHeader.Version, ipHeader.HeaderLength, ipHeader.DifferentiatedServices, ipHeader.TotalLength, ipHeader.Identification,
                                 ipHeader.Flags, ipHeader.FragmentationOffset, ipHeader.TTL, ipHeader.ProtocolType.ToString(), ipHeader.Checksum, "",
                                 udpHeader.SourcePort, udpHeader.DestinationPort, udpHeader.Length, udpHeader.Checksum, udpHeader.Data);

                    if (udpHeader.DestinationPort == "53" || udpHeader.SourcePort == "53")
                    {
                    //    AddRowDNSProtocol RowDNSProtocol = new AddRowDNSProtocol(MakeDNS);
                    //    dgvParamProt.Invoke(RowDNSProtocol, new object[] { udpHeader.Data, Convert.ToInt32(udpHeader.Length) - 8 });
                    }

                    break;

                case Protocol.Unknown:
                    break;
            }

            AddPacketToGrid();

        }

 
// Конвертируем массив байтов в строку        
        private static string ConvertToString(byte[] bytes)
        {
            string s = @"";
            foreach (byte b in bytes)
            {
                string r = ((char)b).ToString();
                s += r;
            }
            return s;
        }

// Конвертируем строку в массив байтов   
        public static byte[] StrToByteArray(string str)
        {
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            return encoding.GetBytes(str);
        }


//Ф-ия выводит информацию о TCP
        private void ShowTCP(String SourcePort, String DestinationPort, String SequenceNumber, String AcknowledgementNumber, String HeaderLength, String Flags, String WindowSize, String Checksum, String UrgentPointer)
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
            this.dgvParamProt.Rows.Add("Source Port:", SourcePort);
            this.dgvParamProt.Rows.Add("Destination Port:", DestinationPort);
            this.dgvParamProt.Rows.Add("Sequence Number: ", SequenceNumber);
              if (AcknowledgementNumber != "")
                {
                    this.dgvParamProt.Rows.Add("Acknowledgement Number: ", AcknowledgementNumber);
                }
            this.dgvParamProt.Rows.Add("Header Length:", HeaderLength);
            this.dgvParamProt.Rows.Add("Flags:", Flags);
            this.dgvParamProt.Rows.Add("Window Size:", WindowSize);
            this.dgvParamProt.Rows.Add("Checksum:", Checksum);
                if (UrgentPointer != "")
                {
                    this.dgvParamProt.Rows.Add("Urgent Pointer:", UrgentPointer);
                }
        }


//Ф-ия выводит информацию о UDP 
        private void ShowUDP(String SourcePort, String DestinationPort, String Length, String Checksum)
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

            dgvParamProt.Rows.Add("Порт источника:", SourcePort);
            dgvParamProt.Rows.Add("Порт приемника:", DestinationPort);
            dgvParamProt.Rows.Add("Длина пакета:", Length);
            dgvParamProt.Rows.Add("Контрольная сумма:", Checksum);
        }


//Ф-ия выводит информацию о DNS
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


// Ф-ия выводит содержимое пакета
        public void ShowDump(byte[] bytes , int len)
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

// Ф-ия выводит содержимое пакета в 2 грида(дампа и параметров протокола)
        public void AdddgvParamProtandAdddgvDump(string numpacket){
            String Path = string.Format("log{0:yyyyMMddHH}.xml", DateTime.Now);
            XmlTextReader reader = null;
            try
            {
                reader = new XmlTextReader(Path);
                reader.WhitespaceHandling = WhitespaceHandling.None;	// пропускаем пустые узлы
                while (reader.Read())
                    if (reader.NodeType == XmlNodeType.Element)
                        if (reader.Name == "Пакет" && reader.AttributeCount != 0)
                        {
                            if (reader.GetAttribute("НомерПакета") == numpacket)
                            {
                                String ProtocolType = reader.GetAttribute("ТипПротокола");
                                if (ProtocolType == "TCP")
                                {
                                    ShowTCP(reader.GetAttribute("ПортИсточника"), reader.GetAttribute("ПортПриемника"), reader.GetAttribute("ПорядковыйНомер"),
                                        reader.GetAttribute("ПодтверждениеКоличества"), reader.GetAttribute("ДлинаЗаголовка"), reader.GetAttribute("ФлагиПротокола"),
                                        reader.GetAttribute("РазмерОкна"), reader.GetAttribute("ПроверочнаяСуммаПротокола"), reader.GetAttribute("УказательСрочности"));

                                    ShowDump(StrToByteArray(reader.GetAttribute("СодержимоеПакета")), Convert.ToInt32(reader.GetAttribute("ДлинаЗаголовка")));
                        
                                }

                                if (ProtocolType == "UDP")
                                {
                                    ShowUDP(reader.GetAttribute("ПортИсточника"), reader.GetAttribute("ПортПриемника"), reader.GetAttribute("ДлинаПротокола"), reader.GetAttribute("ПроверочнаяСуммаПротокола"));
                                    ShowDump(StrToByteArray(reader.GetAttribute("СодержимоеПакета")), Convert.ToInt32(reader.GetAttribute("ДлинаПротокола")));
                                }
                                break;
                            }                            
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


//начинаем сканирование сети  и прием пакетов с последующим парсингом (разбором по частям)
        private void toolStripButton3_Click(object sender, EventArgs e)
        {
            try
            {
                // обнуление счетчика пакетов 
                countpackets = 0;
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


//загрузка формы. проверяем интерфесы. какие существуют на ПК
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

// Очистить все гриды
        private void очиститьВсеToolStripMenuItem_Click(object sender, EventArgs e)
        {           
            this.dgvParamProt.Rows.Clear();
            this.dgvPackets.Rows.Clear();
            this.dgvDump.Rows.Clear();
        }

// Обработчик события нажатия на грид
        private void dgvPackets_Click(object sender, EventArgs e)
        {
            this.Text = (this.dgvPackets.CurrentRow.Index).ToString() + "    ^    " + this.dgvPackets.Rows[this.dgvPackets.CurrentRow.Index].Cells[0].Value;

            String st = this.dgvPackets.Rows[this.dgvPackets.CurrentRow.Index].Cells[0].Value.ToString();
            AdddgvParamProtandAdddgvDump(st);
        }

    }
}
