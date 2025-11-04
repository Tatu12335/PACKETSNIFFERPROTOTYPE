using PacketDotNet;
using PcapDotNet.Core;
using System.Net;
using System.Diagnostics;
using System.Collections.Generic;

using PcapDotNet = PcapDotNet.Packets.Packet;

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
                for (int i = 0; i != allDevices.Count;i++)
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
                    // Call the SelectDevice method to get the users device choice
                    SelectDevice();
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
                    Console.WriteLine(" Finished processing device " );

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

    }
}