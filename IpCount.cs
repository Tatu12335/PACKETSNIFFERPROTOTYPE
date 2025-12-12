using System;

public class Class1
{
    public static Dictionary<string?, int?> pairsSource = new Dictionary<string?, int?>();
    public iPSource()
	{
        static void IpCounter(int count, PcapDotNet.Packets.Packet packet)
        {
            ipV4 =  packet.Ethernet.IpV4.Source.ToString();
            if (pairsSource.ContainsKey(packet.Ethernet.IpV4.Source.ToString()))
            {
                pairsSource[packet.Ethernet.IpV4.Source.ToString()] = pairsSource[packet.Ethernet.IpV4.Source.ToString()] + 1;
            }
            else
            {
                pairsSource.Add(packet.Ethernet.IpV4.Source.ToString(), 1);
            }
        }

        static string _logSourceIp(PcapDotNet.Packets.Packet packet)
        {
            
            return "";
        }
    }
}
