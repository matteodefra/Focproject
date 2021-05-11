//
// Created by erauper on 4/7/19.
//

#ifndef INTERCOM_TCP_CLIENT_H
#define INTERCOM_TCP_CLIENT_H


#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netdb.h>
#include <vector>
#include <errno.h>
#include <thread>
#include <string.h>
#include "client_observer.h"
#include "pipe_ret_t.h"
#include <openssl/pem.h>
#include "util.h"

using namespace std;

#define MAX_PACKET_SIZE 4096


//TODO: REMOVE ABOVE CODE, AND SHARE client.h FILE WITH SERVER AND CLIENT

class TcpClient
{
private:

    // Socket
    int m_sockfd = 0;

    // Determinate the status of the client thread handler
    bool stop = false;
    // Server address
    struct sockaddr_in m_server;
    // Publish-Subscribe: list of all subscribers of this client
    std::vector<client_observer_t> m_subscribers;
    // Thread handler
    std::thread * m_receiveTask = nullptr;
    // Client name
    std::string clientName;

    EVP_PKEY *mykey;
    EVP_PKEY *peerKey;

    bool isChatting = false;

    // Client will also have a private key protected by a password

    // Print the server message on stdout
    void publishServerMsg(const char * msg, size_t msgSize);
    // Print information about server disconnection
    void publishServerDisconnected(const pipe_ret_t & ret);
    // It is called each time a packet arrive from the server
    void ReceiveTask();
    // Clean the thread handler
    void terminateReceiveThread();

public:
    ~TcpClient();

    /** Function used to connect to the server (here security authentication  
     * must be added). sendMsg of course will implement secure communication
     * (through the symmetric exchanged after the authentication)
     */
    pipe_ret_t connectTo(const std::string & address, int port);
    pipe_ret_t sendMsg(const char * msg, size_t size);

    // Check if command is a valid request
    int checkCommandValidity(string msg);

    unsigned char* pswHash(string msg);

    // Function must be called at client start in order to authenticate 
    void authenticateThroughServer();

    // Display all clients connected 
    void displayAllClients();

    // To subscribe client, publish 
    void subscribe(const client_observer_t & observer);
    void unsubscribeAll();
    // void publish(const char * msg, size_t msgSize);

    void processRequest(unsigned char* plaintext_buffer);

    bool getChatting() { return isChatting; }
    void setChatting() { isChatting = true; }

    void setClientName(std::string name) { clientName = name; }
    string getClientName() { return clientName; }

    void setAndStorePeerKey(unsigned char *key);

    void saveMyKey();

    pipe_ret_t finish();
};

#endif //INTERCOM_TCP_CLIENT_H
