
// Dependencies
using Microsoft.VisualBasic.FileIO;
using PacketDotNet;
using PacketDotNet.DhcpV4;
using PacketDotNet.Ieee80211;
using PcapDotNet.Core;
using PcapDotNet.Core.Extensions;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Ip;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Channels;
using System.Xml.Linq;








// End Dependencies




// This is a prototype for a packet sniffer application using PcapDotNet library
// I already wrote the core logic for the project, but it was a mess so i decided to clean it up and start fresh
// I will be adding more features and functionality as I go along
// I also plan to document the code better and make it more user friendly

// For more information on the journey of this project, check the README.md file in the root directory of the repository

namespace PACKETSNIFFERPROTOTYPE
{
    class Program
    {

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

                    // To have an index to start at 1, we have the i index writen as +1
                    Console.Write((i + 1 ) + $".|| " + device.Name);

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
                    StartCapture(allDevices[SelectDevice()]);
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
        public static int SelectDevice()
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

        public static void StartCapture(LivePacketDevice device)
        {
            

            // Placeholder for starting packet capture on the selected device
            Console.Clear();
            Console.BackgroundColor = ConsoleColor.Red;
            Console.WriteLine($" Starting capturing packets on : {device.Name} ctrl + c to stop");
            Console.BackgroundColor = ConsoleColor.Black;

            // Handle Ctrl + C event to stop packet capture gracefully
            Console.CancelKeyPress += new ConsoleCancelEventHandler(HandleCancelKeyPress);


            while (!_IsCancelled)
            {
                
                Thread.Sleep(1000); // Sleep for a short duration to prevent high CPU usage

                using (PacketCommunicator communicator = device.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
                {
                    // Start the capture
                    communicator.ReceivePackets(0, packet =>
                    {

                        IpV4Datagram ipv4Packet = packet.Ethernet.IpV4;
                        IpV6Datagram ipv6Packet = packet.Ethernet.IpV6;
                        packet.DataLink.ToString();

                        // Calls the filter method to filter http/https traffic and analyze the packet
                        FilterHttpTrafic(packet, null, null);




                    });
                    
                }
                



            }
           


        }
        // Handle Ctrl + C event to stop packet capture gracefully and save data to desktop or documents
        private static void HandleCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
        {
            // Prevent the process from terminating immediately
            e.Cancel = true;

            // Save captured data to desktop or documents folder
            Console.WriteLine(" Saving captured data...");

            Console.WriteLine(" Stopping packet capture...");
            
            _IsCancelled = true;
            e.Cancel = false;
            Environment.Exit(0);



        }
        public static void LogPacketDetails(PcapDotNet.Packets.Packet packet)
        {


            var curDir = FileSystem.CurrentDirectory;
            DateTime dateTime = DateTime.Now;


            // Try to get desktop, else try to find documents
            try
            {
                curDir = Environment.GetEnvironmentVariable("USERPROFILE") + "\\Desktop\\";
            }
            catch (DirectoryNotFoundException ex)
            {
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine(" Could not find desktop folder, trying documents folder...");
                Console.BackgroundColor = ConsoleColor.Black;
            }
            catch (Exception ex)
            {
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine($" Unexpected error occured finding desktop folder | ERROR : {ex.Message} |");
                Console.BackgroundColor = ConsoleColor.Black;
            }

            try
            {
                curDir = Environment.GetEnvironmentVariable("USERPROFILE") + "\\Documents\\";
            }
            catch (DirectoryNotFoundException ex)
            {
                // If both desktop and documents folders are not found, save to captured_packets folder in current directory
                Console.WriteLine(" Could not find desktop or documents folder, saving to current directory.");
                FileSystem.CreateDirectory("captured_packets");
                curDir = Environment.GetEnvironmentVariable("captured_packets");
            }
            catch (Exception ex)
            {
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine($" Unexpected error occured finding documents folder | ERROR : {ex.Message} |");
                Console.BackgroundColor = ConsoleColor.Black;
            }
           
            
            try
            {
                File.Create(curDir + $"captured_packets({dateTime}.pcap)");
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
                // Tries to save the captured data to a file without appending
                FileSystem.WriteAllText(
                    Path.Combine(curDir, $"captured_packets{dateTime}.pcap"), $"{packet}", false);
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
        public static void MagicMethod(PcapDotNet.Packets.Packet packet)
        {
           
            IpV4Datagram ipv4Packet = packet.Ethernet.IpV4;
            IpV6Datagram ipv6Packet = packet.Ethernet.IpV6;

            // If its ipV4 packet
            if (ipv4Packet != null)
            {
                if (ipv4Packet.Protocol == IpV4Protocol.Tcp)
                {
                    var tcp = ipv4Packet.Tcp;
                    Console.WriteLine($" TCP Packet | Source : {ipv4Packet.Source} | Destination : {ipv4Packet.Destination} | Source Port : {tcp.SourcePort} | Destination Port : {tcp.DestinationPort} |");
                }
                else if (ipv4Packet.Protocol == IpV4Protocol.Udp)
                {
                    var udp = ipv4Packet.Udp;
                    Console.WriteLine($" UDP Packet | Source : {ipv4Packet.Source} | Destination : {ipv4Packet.Destination} | Source Port : {udp.SourcePort} | Destination Port : {udp.DestinationPort} |");
                }
                else
                {
                    Console.WriteLine($" IPv4 Packet | Source : {ipv4Packet.Source} | Destination : {ipv4Packet.Destination} | Protocol : {ipv4Packet.Protocol} |");
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
        // Returns a the packet
        public static PcapDotNet.Packets.Packet FilterHttpTrafic(PcapDotNet.Packets.Packet packet, UdpDatagram? udp, TcpDatagram? tcp)
        {
            try
            {
                tcp = packet.Ethernet.IpV4.Tcp;
                udp = packet.Ethernet.IpV4.Udp;

                // Check for http and https traffic on both tcp and udp protocols, not sure if this is the best way but i tried
                // I plan on making more filtering logic in the future

                // NOTE : Fix the logic here its messy!!!!!
                if (tcp.DestinationPort == 443 || tcp.SourcePort == 443)
                {
                    Console.BackgroundColor = ConsoleColor.Red;
                    Console.WriteLine(" Tcp https packet detected filtering it out ");
                    Console.BackgroundColor = ConsoleColor.Black;

                   

                    return packet;
                }
                else if (tcp.DestinationPort == 80 || tcp.SourcePort == 80)
                {
                    Console.BackgroundColor = ConsoleColor.Red;
                    Console.WriteLine(" Tcp http packet detected filtering it out");
                    Console.BackgroundColor = ConsoleColor.Black;

                    return packet;
                }
                //  
                if (udp.DestinationPort == 443 || udp.SourcePort == 443)
                {

                    Console.BackgroundColor = ConsoleColor.Red;
                    Console.WriteLine(" Udp https packet detected filtering it out ");
                    Console.BackgroundColor = ConsoleColor.Black;

                   
                    return packet;

                }
                if (udp.DestinationPort == 80 || udp.SourcePort == 80)
                {
                    Console.BackgroundColor = ConsoleColor.Red;
                    Console.WriteLine(" Udp http packet detected filtering it out");
                    Console.BackgroundColor = ConsoleColor.Black;

                    return packet;

                }
                else
                {
                    MagicMethod(packet);
                    return packet;
                }

            }
            catch (Exception e)
            {
                Console.WriteLine($" Unexpected error occured filtering http/s packet| ERROR : {e.Message} |");
                return packet;
            }
        }
        public static void CheckForBadChecksums()
        {
           
        }
        public static void DetectSuspiciousActivity()
        {
            // Placeholder for detecting suspicious activity
            Console.WriteLine(" Detecting suspicious activity...");
        }
        public static void AlertOnSuspiciousActivity()
        {
            // Placeholder for alerting on suspicious activity
            Console.WriteLine(" Alerting on suspicious activity...");
        }
        

      
    }
    
}