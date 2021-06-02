///////////////////////////////////////////////////////////
/////////////////////SERVER EXAMPLE////////////////////////
///////////////////////////////////////////////////////////

// #ifdef SERVER_EXAMPLE

#include <iostream>
#include <signal.h>

#include "include/tcp_server.h"

// declare the server
TcpServer server;

// declare a server observer which will receive incoming messages.
// the server supports multiple observers
server_observer_t observer1;


// on sig_exit, close client
void sig_exit(int s)
{
	cout << "Closing server..." << std::endl;
	pipe_ret_t finishRet = server.finish();
	if (finishRet.success) {
		cout << "Server closed." << std::endl;
	} else {
		cout << "Failed to close server." << std::endl;
	}
	exit(0);
}

// observer callback. will be called when client disconnects
void onClientDisconnected(Client & client) {
    std::cout << "Client: " << client.getIp() << " disconnected: " << client.getInfoMessage() << std::endl;
}

int main(int argc, char *argv[])
{
    signal(SIGINT, sig_exit);

    // start server on port 65123
    pipe_ret_t startRet = server.start(65123);
    if (startRet.success) {
        std::cout << "Server setup succeeded" << std::endl;
    } else {
        std::cout << "Server setup failed: " << startRet.msg << std::endl;
        return EXIT_FAILURE;
    }

    // configure and register observer1
    observer1.incoming_packet_func = nullptr;
    observer1.disconnected_func = onClientDisconnected;
    observer1.wantedIp = "127.0.0.1";
    server.subscribe(observer1);

    // // configure and register observer2
    // observer2.incoming_packet_func = onIncomingMsg2;
    // observer1.disconnected_func = nullptr; //don't care about disconnection
    // observer2.wantedIp = "10.88.0.11"; // use empty string instead to receive messages from any IP address
    // server.subscribe(observer2);

    // receive clients
    while(1) {
        Client client = server.acceptClient(0);
        if (client.isConnected()) {
            std::cout << "Got client with IP: " << client.getIp() << std::endl;
            server.printClients();
        } else {
            std::cout << "Accepting client failed: " << client.getInfoMessage() << std::endl;
        }
        sleep(1);
    }

    return 0;
}

// #endif