

#ifndef INTERCOM_TCP_SERVER_H
#define INTERCOM_TCP_SERVER_H



#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <functional>
#include <cstring>
#include <errno.h>
#include <iostream>
#include "client.h"
#include "server_observer.h"
#include "pipe_ret_t.h"
#include "util.h"
#include <openssl/evp.h>

using namespace std;

#define MAX_PACKET_SIZE 4096

class TcpServer
{
private:

    // Information about server and client
    int m_sockfd;
    struct sockaddr_in m_serverAddress;
    struct sockaddr_in m_clientAddress;
    fd_set m_fds;

    /** Server will keep here a list of public key of all clients
     * (stored in files .pem) and also a list of the symmetric key 
     * it negotiate with each one of them
     */
    EVP_PKEY *serverPrivKey;

    EVP_PKEY *serverDHPrivKey;
    EVP_PKEY *serverDHPubKey;

    // Vector of all clients connected
    std::vector<Client> m_clients;
    // List of all server subscribers
    std::vector<server_observer_t> m_subscribers;

    std::thread * threadHandle;

    // Some server function to print client messages, client disconnection
    // and the receive task (the spawning thread)
    void publishClientMsg(Client & client, const char * msg, size_t msgSize);
    void publishClientDisconnected(Client & client);
    void receiveTask(/*void * context*/);


public:

    // Start server routine
    pipe_ret_t start(int port);

    // Receive a client connection (here must be added the 
    // authentication of the server)
    Client acceptClient(uint timeout);

    //
    void setServerPrivKey(EVP_PKEY *privKey) { serverPrivKey = privKey; }
    EVP_PKEY* getServerPrivKey() { return serverPrivKey; }

    //
    void setServerDHkeypair(EVP_PKEY* privateKey, EVP_PKEY* publicKey) {
        serverDHPrivKey = privateKey;
        serverDHPubKey = publicKey;
    }
    EVP_PKEY* getDHPublicKey() { return serverDHPubKey; }
    EVP_PKEY* getDHPrivateKey() { return serverDHPrivKey; }

    // 
    void loadServerDHKeys();

    // Authentication function (parallel to authentication client)
    void authenticateServer();

    // Delete a client from list (due to disconnection or logout)
    bool deleteClient(Client & client);

    //
    Client& getClient(Client &client);

    //
    void storeRequestingInfo(Client &receivingClient, Client &requestingClient);

    //
    Client& sendRequest(Client &client, std::string message);

    //
    string loginClient(Client &client, std::string message);

    //
    string regClient(Client &client, std::string message);
    
    //
    string createList(Client &client, std::string message);

    //
    void processRequest(Client &client,std::string decryptedMessage);

    // Add or remove eventually new observers
    void subscribe(const server_observer_t & observer);
    void unsubscribeAll();

    /** Send a broadcast message or single client message
     * (need to implement security protocol, and also if sendToAll could
     * be modified in order to send the request to talk)
     * finish() will close the server and free clients resources
     */
    pipe_ret_t sendToAllClients(const char * msg, size_t size);
    pipe_ret_t sendToClient(Client & client, const char * msg, size_t size);
    pipe_ret_t sendCertificate(Client & client);
    pipe_ret_t checkClientIdentity(Client & client,string msg);
    pipe_ret_t finish();
    void printClients();
};



#endif //INTERCOM_TCP_SERVER_H
