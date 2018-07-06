#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include "lib/jsoncpp.cpp"

Json::Value getConfig(char* config_path)
{
	Json::Value config;
	try
    {
        std::ifstream config_file(config_path, std::ifstream::binary);
        config_file >> config;
    } catch(Json::RuntimeError e)
    {
        printf("Could not read configuration file at \"%s\"\n", config_path);
        exit(1);
	}
	return config;
}

long int rxbytes(std::string device_name)
{
    std::string rx_bytes;
    try
    {
        std::string file = "/sys/class/net/" + device_name + "/statistics/rx_bytes";
        std::ifstream rx_bytes_fd(file.c_str(), std::ifstream::binary);
        rx_bytes_fd >> rx_bytes;
    } catch(std::ifstream::failure e)
    {
        printf("Exception: %s\n", e.code());
        exit(1);
    }
    try
    {
        long int ret = std::stol(rx_bytes);
        return ret;
    } catch(std::out_of_range e)
    {
        return 0;
    }
}

long int rxpackets(std::string device_name)
{
    std::string rx_bytes;
    try
    {
        std::string file = "/sys/class/net/" + device_name + "/statistics/rx_packets";
        std::ifstream rx_bytes_fd(file.c_str(), std::ifstream::binary);
        rx_bytes_fd >> rx_bytes;
    } catch(std::ifstream::failure e)
    {
        printf("Exception: %s\n", e.code());
        exit(1);
    }
    try
    {
        long int ret = std::stol(rx_bytes);
        return ret;
    } catch(std::out_of_range e)
    {
        return 0;
    }
}

long int txpackets(std::string device_name)
{
    std::string rx_bytes;
    try
    {
        std::string file = "/sys/class/net/" + device_name + "/statistics/tx_packets";
        std::ifstream rx_bytes_fd(file.c_str(), std::ifstream::binary);
        rx_bytes_fd >> rx_bytes;
    } catch(std::ifstream::failure e)
    {
        printf("Exception: %s\n", e.code());
        exit(1);
    }
    try
    {
        long int ret = std::stol(rx_bytes);
        return ret;
    } catch(std::out_of_range e)
    {
        return 0;
    }
}

long int txbytes(std::string device_name)
{
    std::string tx_bytes;
    try
    {
        std::string file = "/sys/class/net/" + device_name + "/statistics/tx_bytes";
        std::ifstream tx_bytes_fd(file.c_str(), std::ifstream::binary);
        tx_bytes_fd >> tx_bytes;
    } catch(std::ifstream::failure e)
    {
        printf("Exception: %s\n", e.code());
        exit(1);
    }
    try
    {
        long int ret = std::stol(tx_bytes);
        return ret;
    } catch(std::out_of_range e)
    {
        return 0;
    }
}

int handle_ddos(std::string device, char* config_path)
{
    /*
     *  ATTACK HANDLER
	 */
	long int rxbytes_first = rxbytes(device);
	sleep(1);
	long int rxbytes_second = rxbytes(device);
    long int rxbytesps = (rxbytes_second-rxbytes_first);
    
    long int txbytes_first = txbytes(device);
    sleep(1);
    long int txbytes_second = txbytes(device);
    long int txbytesps = (txbytes_second-txbytes_first);

    long int rxpackets1 = rxpackets(device);
    sleep(1);
    long int rxpackets2 = rxpackets(device);
    long int rxpacketsps = (rxpackets2-rxpackets1);

    long int txpackets1 = rxpackets(device);
    sleep(1);
    long int txpackets2 = txpackets(device);
    long int txpacketsps = (txpackets2-txpackets1);

	Json::Value config = getConfig(config_path);
	printf("Detected incoming (D)DoS attack!\n-----\nRX:\t%dBps\nTX:\t%dBps\nRX PPS:\t%d\nTX PPS:\t%d\n", rxbytesps,txbytesps,rxpacketsps,txpacketsps);
	// /usr/sbin/tcpdump -X -nn -i '.$device.' -s 0 -c '.$sample_size.' -w '.$logging_path."/".$filename
	std::string tcpdcmd = "/usr/sbin/tcpdump -X -nn -i " + device + " -s 0 -c 100000 -w " + config["log_directory"].asString() + "/attack.pcap";
    system(tcpdcmd.c_str());
    return 0;
}

int main(int argc, char** argv)
{
    if(argc <= 1)
    {
        printf("Usage: %s <config-path>\n", argv[0]);
        exit(1);
    }
    //std::string path = boost::lexical_cast<string>((char*)argv[1]);
    Json::Value config;
	config = getConfig(argv[1]);
    printf("Logging Directory: %s\n", config["log_directory"].asCString());

    while(1 == 1)
    {
        /*
        *  MAIN LOOP
        * TODO:
        * - support multiple devices like the perl version of DoSMon.
        */
        long int rxbytes_first = rxbytes(config["device"].asString());
        sleep(1);
        long int rxbytes_second = rxbytes(config["device"].asString());
        long int rxbytesps = (rxbytes_second-rxbytes_first);

        long int txbytes_first = txbytes(config["device"].asString());
        sleep(1);
        long int txbytes_second = txbytes(config["device"].asString());
        long int txbytesps = (txbytes_second-txbytes_first);
        
        long int rxpackets1 = rxpackets(config["device"].asString());
        sleep(1);
        long int rxpackets2 = rxpackets(config["device"].asString());
        long int rxpacketsps = (rxpackets2-rxpackets1);

        long int txpackets1 = rxpackets(config["device"].asString());
        sleep(1);
        long int txpackets2 = txpackets(config["device"].asString());
        long int txpacketsps = (txpackets2-txpackets1);


		/*
		 * Check for signs of a potential (D)DoS attack based on configuration thresholds.
		 */
        if(
            rxbytesps >= std::stol(config["thresholds"]["bandwidth"]["bytes_in"].asString()) ||
            txbytesps >= std::stol(config["thresholds"]["bandwidth"]["bytes_out"].asString()) ||
            rxpacketsps >= std::stol(config["thresholds"]["packets"]["in"].asString()) || 
            txpacketsps >= std::stol(config["thresholds"]["packets"]["out"].asString())
        ) {
			/*
			 * Send attack details to DDoS handler
			 */
            handle_ddos(config["device"].asString(), argv[1]);
            sleep(300);
        }
    }
    return 0;
}