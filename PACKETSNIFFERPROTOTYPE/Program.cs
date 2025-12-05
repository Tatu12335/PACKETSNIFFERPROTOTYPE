using PacketDotNet;
using PcapDotNet.Core;
using System.Net;
using System.Diagnostics;
using System.Collections.Generic;
using PcapDotNet = PcapDotNet.Packets.Packet;
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

            // Handle Ctrl + C event to stop packet capture gracefully
            Console.CancelKeyPress += new ConsoleCancelEventHandler(HandleCancelKeyPress);  

            // Retrieve the device list
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }
            else
            {
                Console.WriteLine("The following interfaces are available:");
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
                    // Call the start capture method with the selected device
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
                    // this is a placeholder for any cleanup code if needed in the future
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
                throw new ArgumentOutOfRangeException("Device index is out of range.");
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
            Console.WriteLine($" Starting capturing packets on : {device.Name} ctrl + c to stop");
            
            while (!_IsCancelled)
            {

                using(PacketCommunicator communicator = device.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
                {
                    // Start the capture
                    communicator.ReceivePackets(0, packet =>
                    {

                        IpV4Datagram ipv4Packet = packet.Ethernet.IpV4;


                        // Process each packet
                        Console.WriteLine($"Source : {ipv4Packet.Source} | Destinatination : {ipv4Packet.Destination} | Payload : {ipv4Packet.Payload} | Protocol  : {ipv4Packet.Protocol} |");

                    });
                    
                }
                



            }
           


        }
        // Handle Ctrl + C event to stop packet capture gracefully and save data to desktop or documents.
        private static void HandleCancelKeyPress(object? sender , ConsoleCancelEventArgs e)
        {
            e.Cancel = true;
            

            Console.WriteLine(" Saving captured data...");
            var curDir = FileSystem.GetDirectoryInfo("desktop");

            if (curDir == null)
            {
                curDir = FileSystem.GetDirectoryInfo("documents");
            }


            Console.WriteLine(" Stopping packet capture...");
            Console.WriteLine($" Logging captured packets to a location {curDir} ");

            _IsCancelled = true;
            FileSystem.WriteAllText(Path.Combine(curDir.FullName, "captured_packets_log.pcap"));


        }
        public static void AlertOnSuspiciousActivity()
        {
            // Placeholder for alerting on suspicious activity
            Console.WriteLine(" Alerting on suspicious activity...");
        }
        

      
    }
    
}