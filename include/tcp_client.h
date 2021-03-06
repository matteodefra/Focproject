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

    bool isChatting = false;
    bool AuthSuccess = false;
    bool isAdmin = false;

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

    bool sendingRequest = false;
    // My RSA private key
    EVP_PKEY *mykey_RSA;
    // My DH publick key
    EVP_PKEY *mykey_pub;
    // Peer DH public key (REQ)
    EVP_PKEY *peerKey;
    // Server RSA public key
    EVP_PKEY *serverRSAKey;
    // Server DH public key
    EVP_PKEY *serverDHKey;    
    // Peer RSA pubkey (to verify signature)
    EVP_PKEY *peerRSAKey;
    // DH pubkey for peer to peer communication
    EVP_PKEY *mypubkey_p2p;

    unsigned char* nonceAccept;


    unsigned int c_counter;
    unsigned int s_counter;

    unsigned int myPeerCounter;
    unsigned int peerCounter;
    
    ~TcpClient();

    /** Function used to connect to the server (here security authentication  
     * must be added). sendMsg of course will implement secure communication
     * (through the symmetric exchanged after the authentication)
     */
    pipe_ret_t connectTo(const std::string & address, int port);
    pipe_ret_t sendMsg(const char * msg, size_t size);

    // Check if command is a valid request
    int checkCommandValidity(string msg);

    unsigned char* pswHash(string msg,bool reg);

    // Function must be called at client start in order to authenticate the server, verifying its certificate
    bool authenticateServer();
    bool clientRecognition();

    // To subscribe client, publish 
    void subscribe(const client_observer_t & observer);
    void unsubscribeAll();

    void processRequest(unsigned char* plaintext_buffer,int bytesReceived);

    // Getter and setter
    bool getChatting() { return isChatting; }
    void setNotChatting() { isChatting = false; }
    void setChatting() { isChatting = true; }

    bool getAdmin() { return isAdmin; }
    void setAdmin() { isAdmin = true; }

    bool getAuthSuccess() { return AuthSuccess; }
    void setAuthSuccess(bool x) { AuthSuccess = x; }

    void setClientName(std::string name) { clientName = name; }
    string getClientName() { return clientName; }

    void setAndStorePeerKey(unsigned char *key);

    pipe_ret_t sendQuitMessage(const char* msg, size_t size);

    void saveMyKey();

    unsigned char* insertNonceAccept(string msg);

    int generateDHKeypairs();
    int generateDHKeypairsForP2P();

    pipe_ret_t sendAndReceiveSignature();
    pipe_ret_t receiveAndSendSignature();

    pipe_ret_t finish();
};

#endif //INTERCOM_TCP_CLIENT_H
