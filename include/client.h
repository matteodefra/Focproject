#ifndef INTERCOM_CLIENT_H
#define INTERCOM_CLIENT_H


#include <string>
#include <thread>
#include <functional>
#include <openssl/evp.h>

// Used by Server to monitor clients
class Client {

private:

    // Variable for client connection
    int m_sockfd = 0;
    std::string m_ip = "";
    std::string m_errorMsg = "";
    std::string m_name = "";

    // Istance of the requesting client (to allow forwarding)
    std::string ipChattingClient;
    int socketChattingClient;

    // Public key instance of client (stored a priori)
    EVP_PKEY *clientPubKeyRSA;
    // DH key received from client after authentication
    EVP_PKEY *clientPubKeyDH;

    /** Shared symmetric key AES128 bit to use for symmetric communication
     *  Here client will also contain the shared symmetric key negotiated 
     *  in the beginning
     */
    // EVP_PKEY* serverClientSymmetricKey;

    // Monitor online status of client
    bool m_isConnected = false;

    // Needed to monitor the status of the chat
    bool m_isChatting = false;

    // Authentication flag
    bool m_isAuthenticated = false;

    // Pending request

    bool m_hasRequest = false;

    // Logged

    bool m_isLogged = false;

    // Handler thread for the client thread 
    std::thread * m_threadHandler = nullptr;

public:

    ~Client();
    bool operator ==(const Client & other);

    // Setter and getter
    void setFileDescriptor(int sockfd) { m_sockfd = sockfd; }
    int getFileDescriptor() const { return m_sockfd; }

    void setIp(const std::string & ip) { m_ip = ip; }
    std::string getIp() const { return m_ip; }

    void recoverPublicKey();

    void setErrorMessage(const std::string & msg) { m_errorMsg = msg; }
    std::string getInfoMessage() const { return m_errorMsg; }

    void setConnected() { m_isConnected = true; }
    void setDisconnected() { m_isConnected = false; }
    bool isConnected() { return m_isConnected; }


    // Login

    void setLogged() { m_isLogged = true; }
    void resetLogged() { m_isLogged = false; }
    bool isLogged() { return m_isLogged; }

    // Will be managed by server, to reject or accept the "request to talk"
    void setChatting() { m_isChatting = true; }
    void setNotChatting() { m_isChatting = false; }
    bool isChatting() { return m_isChatting; }

    // Will be managed by server, to reject or accept the "request to talk"
    void setAuthenticated() { m_isAuthenticated = true; }
    void setNotAuthenticated() { m_isAuthenticated = false; }
    bool isAuthenticated() { return m_isAuthenticated; }

    //Will be managed by server, to reject or accept the "request to talk"
    void setRequest() { m_hasRequest = true; }
    void resetRequest() { m_hasRequest = false; }
    bool hasRequest() { return m_hasRequest; }
    

    // Methods to set and get shared secret between server and client
    void setServerClientSharedKey();
    // EVP_PKEY* getServerClientSharedSecret() {return serverClientSymmetricKey;}

    void setClientName(const std::string & name) { m_name.erase(m_name.begin(),m_name.end()); m_name = name; }
    std::string getClientName() const { return m_name; }

    void setChattingClientInfo(const std::string & ip,int socket) { 
        ipChattingClient.erase(ipChattingClient.begin(),ipChattingClient.end()); 
        ipChattingClient = ip; 
        socketChattingClient = socket;    
    }
    std::string getChattingClientIp() const { return ipChattingClient; }
    int getChattingClientSocket() const { return socketChattingClient; }

    void setClientKeyDH(EVP_PKEY *pubkey) { clientPubKeyDH = pubkey; }
    EVP_PKEY* getClientKeyDH() { return clientPubKeyDH; } 

    void setClientKeyRSA(EVP_PKEY *pubkey) { clientPubKeyRSA = pubkey; }
    EVP_PKEY* getClientKeyRSA() { return clientPubKeyRSA; } 

    void setThreadHandler(std::function<void(void)> func) { m_threadHandler = new std::thread(func);}

};


#endif //INTERCOM_CLIENT_H
