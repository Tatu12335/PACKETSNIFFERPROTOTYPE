// Dependencies
using Microsoft.VisualBasic.FileIO;
using PcapDotNet.Core;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;
using System.Net;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.CompilerServices;
using System.Linq;

// End Dependencies


// This is a prototype for a packet sniffer application using PcapDotNet library
// I already wrote the core logic for the project, but it was a mess so i decided to clean it up and start fresh
// I will be adding more features and functionality as I go along
// I also plan to document the code better and make it more user friendly

// For more information on the journey of this project, check the README.md file in the root directory of the repository
// Im trying my best to make this a good learning experience for myself and others
// You might be thinking why i didnt do oop for this project, well its because im still learning c# and i wanted to keep it simple for now
// And since i didnt do oop theres really no reason why this cant be a single file project and public private modifiers are kinda useless here so i just mark everything private 

// 600 lines of code later... i thought to myself, why not split this into multiple files and use oop

// Hours wasted : 9:30

namespace PACKETSNIFFERPROTOTYPE
{
    class Program
    {
        private const string APP_VERSION = "0.2.0-Prototype";


        // Datetime for when the application started
        private static DateTime _startTime { get; } = DateTime.UtcNow;

        // A list to store captured packets temporarily
        private static List<string> capturedPackets = new List<string?>();
        // A list to store flags detected in packets
        private static List<string> Flags = new List<string?>();
        // A dictionary for ip addresses and when they sent packets
        public static Dictionary<string,int?> pairsSource = new Dictionary<string?, int?>();
        // A dictionary for destination ip addresses and when they received packets
       // private static Dictionary<string?, int?> pairsDestination = new Dictionary<string?, int?>();

        static void Main(string[] args)
        {
            // Retrieve the device list
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
            if (allDevices.Count == 0)
            {
                // If count is 0 there are no interfaces found
                Console.WriteLine(" No interfaces found! Make sure WinPcap is installed.");
                return;
            }
            else
            {
                // Else list the Interfaces
                Console.WriteLine(" The following interfaces are available : ");
                Console.WriteLine();
                for (int i = 0; i != allDevices.Count; i++)
                {
                    LivePacketDevice device = allDevices[i];

                    // To have an index to start at 1, we have the i + 1
                    Console.Write((i + 1) + $".|| " + device.Name);

                    if (device.Description != null)
                    {
                        Console.WriteLine(" (" + device.Description + ")");
                    }
                    else
                    {
                        Console.WriteLine(" (No description available)");
                    }
                }
                try
                {
                    // Call the start capture method with the selected device method
                    _StartCapture(allDevices[_SelectDevice()]);
                }
                catch (FormatException)
                {
                    // In case of invalid input
                    Console.WriteLine(" Invalid input. Please enter a valid number.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine(" Error selecting device: " + ex.Message);
                }
                finally
                {
                    // This is a placeholder for any cleanup code if needed in the future
                    Console.WriteLine(" Finished processing device ");

                }
            }
        }
        private static int _SelectDevice()
        {
            // Prompt the user to select a device
            Console.WriteLine(" Enter the number of the device you want to listen on: ");

            // Read the user input anad convert it to an integer, adjusting for zero-based index
            int deviceIndex = int.Parse(Console.ReadLine() ?? "0") - 1;

            // Checks if the device index is valid
            if (deviceIndex < 0 || deviceIndex >= LivePacketDevice.AllLocalMachine.Count)
            {
                throw new ArgumentOutOfRangeException(" Device index is out of range.");
            }
            // Returns the selected device index
            else
            {
                return deviceIndex;
            }
        }
        private static bool _IsCancelled = false;

        private static void _StartCapture(LivePacketDevice device)
        {
            // Placeholder for starting packet capture on the selected device
            Console.Clear();
            Console.BackgroundColor = ConsoleColor.Red;
            Console.WriteLine($" Starting capturing packets on : {device.Name} ctrl + c to stop");
            Console.BackgroundColor = ConsoleColor.Black;

            // Handle Ctrl + C event to stop packet capture gracefully
            Console.CancelKeyPress += new ConsoleCancelEventHandler(_HandleCancelKeyPress);


            while (!_IsCancelled)
            {

                Thread.Sleep(2000); // Sleep for a short duration to prevent high CPU usage

                using (PacketCommunicator communicator = device.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 2000))
                {
                    // Start the capture
                    communicator.ReceivePackets(0, packet =>
                    {

                        IpV4Datagram ipv4Packet = packet.Ethernet.IpV4;
                        IpV6Datagram ipv6Packet = packet.Ethernet.IpV6;
                         
                        // Calls the filter method to filter http/https traffic and analyze the packet
                        _FilterHttpTrafic(packet);
                    });

                }

            }

        }

        // Handle Ctrl + C event to stop packet capture gracefully and save data to desktop or documents
        private static void _HandleCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
        {

            // Prevent the process from terminating immediately
            e.Cancel = true;

            // Save captured data to desktop or documents folder, see _LogPacketDetails method for more info
            Console.WriteLine(" Saving captured data...");

            Console.WriteLine(" Stopping packet capture...");

            _IsCancelled = true;
            e.Cancel = false;

            string allCapturedPackets = string.Join(" \n ", capturedPackets.ToList());
            _LogPacketDetails(allCapturedPackets);
            string allFlags = string.Join(" \n ", Flags.ToList());
            _LogPacketDetails(allFlags);




            Environment.Exit(0);

        }
        // This method logs the packet details to a file on the desktop or documents folder
        // In case both folders are not found, it saves to a captured_packets folder in the current directory
        // I hate this method but it works for now, will refactor later
        private static void _LogPacketDetails(string packet)
        {
            var curDir = FileSystem.CurrentDirectory;

            DateTime fixedTime = _startTime;

            // For debugging purposes
            Console.WriteLine(" Attempting to save captured data...");
            
            // Try to get desktop
            try
            {
                curDir = Environment.GetEnvironmentVariable("USERPROFILE") + "\\Desktop\\";

            }
            catch (DirectoryNotFoundException ex)
            {
                // If desktop folder is not found, try documents folder
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine(" Could not find desktop folder, trying documents folder...");
                Console.BackgroundColor = ConsoleColor.Black;
                //
                try
                {
                    curDir = Environment.GetEnvironmentVariable("USERPROFILE") + "\\Documents\\";
                }
                catch (DirectoryNotFoundException dex)
                {
                    // If both desktop and documents folders are not found, save to captured_packets folder in current directory
                    Console.WriteLine($" Could not find desktop or documents folder, saving to current directory. {dex.Message}");
                    FileSystem.CreateDirectory("captured_packets");
                    curDir = Environment.GetEnvironmentVariable("captured_packets");
                }
                catch (Exception exx)
                {
                    Console.BackgroundColor = ConsoleColor.Red;
                    Console.WriteLine($" Unexpected error occured finding documents folder | ERROR : {exx.Message} |");
                    Console.BackgroundColor = ConsoleColor.Black;
                }
            }
            catch (Exception ex)
            {
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine($" Unexpected error occured finding desktop folder | ERROR : {ex.Message} |");
                Console.BackgroundColor = ConsoleColor.Black;
            }
            try
            {
                // do nothing, just testing access to the directory
            }
            catch (Exception ex)
            {
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine($" Unexpected error occured creating file | ERROR : {ex.Message} |");
                Console.BackgroundColor = ConsoleColor.Black;
            }
            Console.BackgroundColor = ConsoleColor.Red;
            Console.WriteLine($" Logging captured packets to a location (\"{curDir}\") ");
            Console.BackgroundColor = ConsoleColor.Black;
            try
            {
                FileSystem.WriteAllText(
                    Path.Combine(curDir, $"captured_packets({_startTime}).pcap"), $"{packet}", false);
            }
            catch (UnauthorizedAccessException uaEx)
            {
                // Handle unauthorized access exception
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine($" Access denied saving the data to a file | ERROR : {uaEx.Message} |");
                Console.BackgroundColor = ConsoleColor.Black;
            }
            catch (IOException ioEx)
            {
                // Handle I/O exception
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine($" I/O error occured saving the data to a file | ERROR : {ioEx.Message} |");
                Console.BackgroundColor = ConsoleColor.Black;
            }
            catch (Exception ex)
            {
                // Handle any other exceptions
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine($" Unexpected error occured saving the data to a file | ERROR : {ex.Message} |");
                Console.BackgroundColor = ConsoleColor.Black;
            }
        }
        // This method analyzes the packet and prints relevant information
        // Sorry for the name, couldnt think of a better one at the time
        private static void _MagicMethod(PcapDotNet.Packets.Packet packet)
        {
            IpV4Datagram ipv4Packet = packet.Ethernet.IpV4;
            IpV6Datagram ipv6Packet = packet.Ethernet.IpV6;

            // NOTE : Add more protocol analysis in the future 
            // If its ipV4 packet
            if (ipv4Packet != null)
            {
                if (ipv4Packet.Protocol == IpV4Protocol.Tcp)
                {
                    var tcp = ipv4Packet.Tcp;
                    string Packet = $" TCP Packet | Source : {ipv4Packet.Source} | Destination : {ipv4Packet.Destination} | Source Port : {tcp.SourcePort} | Destination Port : {tcp.DestinationPort} |";

                    _CheckProtocolFlags(packet);

                    _LogPacketFlagsToTheList(Packet, packet);
                    
                    capturedPackets.Add(Packet);
                    Console.WriteLine(Packet);
                }
                else if (ipv4Packet.Protocol == IpV4Protocol.Udp)
                {
                    var udp = ipv4Packet.Udp;
                    string Packet = $" UDP Packet | Source : {ipv4Packet.Source} | Destination : {ipv4Packet.Destination} | Source Port : {udp.SourcePort} | Destination Port : {udp.DestinationPort} |";

                    capturedPackets.Add(Packet);
                    Console.WriteLine(Packet);
                }
                else
                {
                    string Packet = $" IPv4 Packet | Source : {ipv4Packet.Source} | Destination : {ipv4Packet.Destination} | Protocol : {ipv4Packet.Protocol} |"; ;

                    capturedPackets.Add(Packet);
                    Console.WriteLine(Packet);
                    _DetectStealhScans(new List<string?> { ipv4Packet.Source.ToString(), ipv4Packet.Destination.ToString() });
                }

            }
            // Else if its ipV6 packet
            else if (ipv6Packet != null)
            {
                Console.WriteLine(" Is ipv6");
            }
            // Else its a non ip packet 
            else
            {
                Console.WriteLine(" Non ip packet");
            }
        }

        // Despite what the name says this is supposed to filter http AND https traffic
        // I will be adding more filtering logic in the future
        private static void _FilterHttpTrafic(PcapDotNet.Packets.Packet packet)
        {
            try
            {
                var eth = packet.Ethernet;
                var ipv4 = eth?.IpV4;
                var ipv6 = eth?.IpV6;

                // If neither IPv4 nor IPv6, just analyze and return
                if (ipv4 == null && ipv6 == null)
                {
                    _MagicMethod(packet);
                    return;
                }

                // Helper local to check ports and print/filter
                static bool IsFiltered(ushort? src, ushort? dst, string protocol)
                {
                    if (src == 443 || dst == 443)
                    {
                        Console.BackgroundColor = ConsoleColor.Red;
                        Console.WriteLine($" {protocol} https packet detected — filtering it out ");
                        Console.BackgroundColor = ConsoleColor.Black;
                        return true;
                    }
                    if (src == 80 || dst == 80)
                    {
                        Console.BackgroundColor = ConsoleColor.Red;
                        Console.WriteLine($" {protocol} http packet detected — filtering it out ");
                        Console.BackgroundColor = ConsoleColor.Black;
                        return true;
                    }
                    return false;
                }

                // Check IPv4 transport layers first
                if (ipv4 != null)
                {
                    if (ipv4.Tcp != null)
                    {
                        if (IsFiltered(ipv4.Tcp.SourcePort, ipv4.Tcp.DestinationPort, "TCP"))
                            return;
                    }

                    if (ipv4.Udp != null)
                    {
                        if (IsFiltered(ipv4.Udp.SourcePort, ipv4.Udp.DestinationPort, "UDP"))
                            return;
                    }

                    // Not filtered, analyze
                    _MagicMethod(packet);
                    return;
                }

                // Check IPv6 transport layers
                if (ipv6 != null)
                {
                    if (ipv6.Tcp != null)
                    {
                        if (IsFiltered(ipv6.Tcp.SourcePort, ipv6.Tcp.DestinationPort, "TCP/IPv6"))
                            return;
                    }

                    if (ipv6.Udp != null)
                    {
                        if (IsFiltered(ipv6.Udp.SourcePort, ipv6.Udp.DestinationPort, "UDP/IPv6"))
                            return;
                    }

                    _MagicMethod(packet);
                    return;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($" Unexpected error occured filtering http/s packet | ERROR : {e.Message} |");
            }
        }
        private static string _LogPacketFlagsToTheList(string? flagInfo, PcapDotNet.Packets.Packet? packet)
        {
            try
            {
                Flags.Add(flagInfo);
                return "\n";

            }
            catch (Exception e) 
            {
                if (packet == null)
                {
                    return $" Unexpeted error occured during saving the flags of a null packet | ERROR : {e.Message}";
         
                }
                else
                {
                    return $" Unexpeted error occured during saving the flags of the packet : {packet.ToString()} | ERROR : {e.Message}";
                }
            }
        }
        private static string _CheckProtocolFlags(PcapDotNet.Packets.Packet packet)
        {

            var eth = packet.Ethernet;
            var ipv4 = eth?.IpV4;
            var ipv6 = eth?.IpV6;



            // Check for IPv4 flags
            if (ipv4 != null)
            {
                // Check for TCP/IPv4 flags
                if (ipv4.Tcp != null)
                {
                    // Analyze TCP/IPv4 flags
                    switch (ipv4.Tcp)
                    {

                        case var t when t.IsSynchronize:               
                            string flag_Syn = $" TCP SYN flag detected on packet : {packet.ToString()}";
                            Console.BackgroundColor = ConsoleColor.Magenta;
                            Console.Write(flag_Syn + t);
                            Console.BackgroundColor = ConsoleColor.Black;
                            return _LogPacketFlagsToTheList(flag_Syn,packet);

                        case var t when t.IsAcknowledgment:
                            string flag_Ack =  $" TCP ACK flag detected on packet : {packet.ToString()}";
                            Console.BackgroundColor= ConsoleColor.Magenta;
                            Console.Write(flag_Ack + t);
                            Console.BackgroundColor = ConsoleColor.Black;
                            return _LogPacketFlagsToTheList(flag_Ack,packet);

                        case var t when t.IsFin:
                            string flag_Fin = $" TCP FIN flag detected on packet : {packet.ToString()}";
                            Console.BackgroundColor = ConsoleColor.Magenta;
                            Console.Write(flag_Fin + t);
                            Console.BackgroundColor = ConsoleColor.Black;
                            return _LogPacketFlagsToTheList(flag_Fin, packet);

                        case var t when t.IsReset:
                            string flag_Rst =  $" TCP RST flag detected on packet : {packet.ToString()}";
                            Console.BackgroundColor = ConsoleColor.Magenta;
                            Console.Write(flag_Rst + t);
                            Console.BackgroundColor = ConsoleColor.Black;
                            return _LogPacketFlagsToTheList(flag_Rst, packet);

                        case var t when t.IsPush:
                            string flag_Psh =  $" TCP PSH flag detected on packet : {packet.ToString()}";
                            Console.BackgroundColor = ConsoleColor.Magenta;
                            Console.Write(flag_Psh + t);
                            Console.BackgroundColor = ConsoleColor.Black;
                            return _LogPacketFlagsToTheList(flag_Psh, packet);

                        case var t when t.IsUrgent:
                            string flag_Urg = $" TCP URG flag detected on packet : {packet.ToString()}";
                            Console.BackgroundColor = ConsoleColor.Magenta;
                            Console.Write(flag_Urg + t);
                            Console.BackgroundColor = ConsoleColor.Black;
                            return _LogPacketFlagsToTheList(flag_Urg, packet);  
                    }
                }
            }
            // Check for IPv6 flags
            if (ipv6 != null)
            {
                // Check for TCP/IPv6 flags
                if (ipv6.Tcp != null)
                {
                    // Analyze TCP/IPv6 flags
                    switch (ipv6.Tcp)
                    {
                        case var t when t.IsSynchronize:
                            string flag_Syn = $" TCP/IPv6 SYN flag detected on packet : {packet.ToString()}";
                            Console.BackgroundColor = ConsoleColor.Magenta;
                            Console.Write(flag_Syn + t);
                            Console.BackgroundColor = ConsoleColor.Black;
                            return _LogPacketFlagsToTheList(flag_Syn, packet);

                        case var t when t.IsAcknowledgment:
                            string flag_Ack = $" TCP/IPv6 ACK flag detected on packet : {packet.ToString()}";
                            Console.BackgroundColor = ConsoleColor.Magenta;
                            Console.Write(flag_Ack + t);
                            Console.BackgroundColor = ConsoleColor.Black;
                            return _LogPacketFlagsToTheList(flag_Ack, packet);

                        case var t when t.IsFin:
                            string flag_Fin = $" TCP/IPv6 FIN flag detected on packet : {packet.ToString()}";
                            Console.BackgroundColor = ConsoleColor.Magenta;
                            Console.Write(flag_Fin + t);
                            Console.BackgroundColor = ConsoleColor.Black;
                            return _LogPacketFlagsToTheList(flag_Fin, packet);

                        case var t when t.IsReset:
                            string flag_Rst = $" TCP/IPv6 RST flag detected on packet : ";
                            Console.BackgroundColor = ConsoleColor.Magenta;
                            Console.Write(flag_Rst + t);
                            Console.BackgroundColor = ConsoleColor.Black;
                            return _LogPacketFlagsToTheList(flag_Rst, packet);

                        case var t when t.IsPush:
                            string flag_Psh = $" TCP/IPv6 PSH flag detected on packet : ";
                            Console.BackgroundColor = ConsoleColor.Magenta;
                            Console.Write(flag_Psh + t);
                            Console.BackgroundColor = ConsoleColor.Black;
                            return _LogPacketFlagsToTheList(flag_Psh, packet);

                        case var t when t.IsUrgent:
                            string flag_Urg = $" TCP/IPv6 URG flag detected on packet : ";
                            Console.BackgroundColor = ConsoleColor.Magenta;
                            Console.Write(flag_Urg + t);
                            Console.BackgroundColor = ConsoleColor.Black;
                            return _LogPacketFlagsToTheList(flag_Urg, packet);
                    }
                }
            
            }
            return $" No flags detected on packet : {packet.ToString()}";
        }
        private static void _DetectStealhScans(List<string?> addresses )
        {
            // Placeholder for detecting stealth scans
            Console.Write(" Detecting stealth scans...");
            
            for(int i = 0; i < addresses.Count; i++)
            {
                var address = addresses[i];
                
            }
            var groupedAddresses = addresses.GroupBy(addr => addr)
                                          .Select(group => new { Address = group.Key, Count = group.Count() })
                                          .Where(g => g.Count > 10); 
            Console.WriteLine(groupedAddresses);


        }
        private static void _CheckForBadChecksums()
        {

        }
        private static bool _DetectPortScans(PcapDotNet.Packets.Packet packet)
        {
            
            var ipv4 = packet.IpV4;
            

            if (ipv4 != null)
            {
                // Check for TCP/IPv4 port scans, I decided to get the protocols separately for easier reading and later expansion.
                if (ipv4.Tcp != null)
                {
                    // Placeholder for port scan detection logic
                    

                }
                else if (ipv4.Udp!= null)
                {
                    // Placeholder for port scan detection logic

                }
                else
                {
                    // Placeholder for other protocol port scan detection logic
                }
            }


            return false;
        }
        private static void _DetectSuspiciousActivity()
        {
            // Placeholder for detecting suspicious activity
            Console.Write(" Detecting suspicious activity...");
        }
        private static void _AlertOnSuspiciousActivity()
        {
            // Placeholder for alerting on suspicious activity
            Console.WriteLine(" Alerting on suspicious activity...");
        }
    }
}