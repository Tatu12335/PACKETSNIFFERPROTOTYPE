
// Dependencies
using PcapDotNet.Core;
using System.Net;
using System.Diagnostics;
using System.Collections.Generic;
using PcapDotNet.Core.Extensions;
using System.Xml.Linq;
using PcapDotNet.Packets;
using System.Net.Sockets;
using PacketDotNet.DhcpV4;
using System.Runtime.CompilerServices;
using System.Collections;
using System.Globalization;
using System.Net.NetworkInformation;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Ip;
using PacketDotNet.Ieee80211;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Icmp;
using Microsoft.VisualBasic.FileIO;
using System.ComponentModel.DataAnnotations;
using System.Reflection.PortableExecutable;
using System.Threading.Channels;
using PacketDotNet;
using System.Threading;








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
                Console.WriteLine(" No interfaces found! Make sure WinPcap is installed.");
                return;
            }
            else
            {
                Console.WriteLine(" The following interfaces are available : ");
                Console.WriteLine();
                for (int i = 0; i != allDevices.Count; i++)
                {

                    LivePacketDevice device = allDevices[i];

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
                    StartCapture(allDevices[SelectDevice()]);
                }
                catch (FormatException)
                {
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

                        MagicMethod(packet);




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
            var curDir = FileSystem.GetDirectoryInfo("desktop");


            try
            {
                curDir = FileSystem.GetDirectoryInfo("documents");
            }
            catch( DirectoryNotFoundException ex)
            {
                // If both desktop and documents folders are not found, save to captured_packets folder in current directory
                Console.WriteLine(" Could not find desktop or documents folder, saving to current directory.");
                FileSystem.CreateDirectory("captured_packets");
                curDir = FileSystem.GetDirectoryInfo("captured_packets");
            }
               

            

            Console.WriteLine(" Stopping packet capture...");
            Console.BackgroundColor = ConsoleColor.Red;
            Console.WriteLine($" Logging captured packets to a location (\"{curDir}\") ");

            _IsCancelled = true;

            try
            {
                // Tries to save the captured data to a file without appending
                FileSystem.WriteAllText(
                    Path.Combine(curDir.FullName, "captured_packets_log.pcap"), $"", false);
            }
            catch (UnauthorizedAccessException uaEx)
            {
                // Handle unauthorized access exception
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine($" Access denied saving the data to a file | ERROR : {uaEx.Message} |");
            }
            catch (IOException ioEx)
            {
                // Handle I/O exception
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine($" I/O error occured saving the data to a file | ERROR : {ioEx.Message} |");
                
            }
            catch (Exception ex)
            {
                // Handle any other exceptions
                Console.BackgroundColor = ConsoleColor.Red;
                Console.WriteLine($" Unexpected error occured saving the data to a file | ERROR : {ex.Message} |");
              
            }
            finally
            {
                // Exit the application gracefully
                e.Cancel = false;
                Console.WriteLine(" Packet capture stopped. Exiting application...");
                Console.BackgroundColor = ConsoleColor.Red;
                Console.BackgroundColor = ConsoleColor.Black;
                Environment.Exit(0);

            }


        }
        public static void MagicMethod(PcapDotNet.Packets.Packet packet)
        {
           
            IpV4Datagram ipv4Packet = packet.Ethernet.IpV4;
            IpV6Datagram ipv6Packet = packet.Ethernet.IpV6;

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
            else if (ipv6Packet != null)
            {
                Console.WriteLine(" Is ipv6");
            }
            else
            {
                Console.WriteLine(" Non ip packet");
            }
        }
        public static void AlertOnSuspiciousActivity()
        {
            // Placeholder for alerting on suspicious activity
            Console.WriteLine(" Alerting on suspicious activity...");
        }
        

      
    }
    
}