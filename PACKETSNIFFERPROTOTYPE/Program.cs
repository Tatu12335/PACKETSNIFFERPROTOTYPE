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
            int[] ints = { 1, 2, 3, 4, 5 };

            




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
        public static void StartCapture(LivePacketDevice device)
        {
            // Placeholder for starting packet capture on the selected device
            Console.Clear();
            Console.WriteLine($" Starting capturing packets on : {device.Name} ctrl + c to stop");
            
            while (true)
            {

                using(PacketCommunicator communicator = device.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
                {
                    // Start the capture
                    communicator.ReceivePackets(0, packet =>
                    {
                        // Process each packet
                        Console.WriteLine(packet.IpV4.ToString());

                    });
                }
               
                
               

            }
            

        }
        // Placeholder for checking traffic patterns
        public static void CheckForTraffic(PacketCommunicator communicator, LivePacketDevice selectedDevice)
        {

            Console.WriteLine(" Checking for specific traffic patterns...");
            while (true)
            {
                //communicator =  selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000);

                for (int i = 0; i < 10; i++)
                {
                    communicator.ReceivePackets(0, packet =>
                    {
                        // Analyze each packet for specific patterns
                       
                        Console.WriteLine(" Analyzing packet for patterns...");
                        

                        if (packet.Count >= 0 )
                        {
                            Console.WriteLine($"Device : {selectedDevice}. Doesnt have traffic");
                        }
                        else
                        {
                            Console.WriteLine($"Device : {selectedDevice}. Has traffic");
                        }

                        Task.Delay(1000).Wait();
                    });
                }
            }




        }
        public static void AlertOnSuspiciousActivity()
        {
            // Placeholder for alerting on suspicious activity
            Console.WriteLine(" Alerting on suspicious activity...");
        }
        public static void SaveCapturedData()
        {
            // Placeholder for saving captured data
            Console.WriteLine(" Saving captured data...");
        }

        public static void LogPacketDataToFile()
       {
            // Placeholder for logging packet data
            Console.WriteLine(" Logging packet data...");
       }
    }
    
}