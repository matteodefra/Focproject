#ifndef INTERCOM_CLIENT_H
#define INTERCOM_CLIENT_H


#include <string>
#include <thread>
#include <functional>

// Used by Server to monitor clients
class Client {

private:

    // Variable for client connection
    int m_sockfd = 0;
    std::string m_ip = "";
    std::string m_errorMsg = "";

    // Monitor online status of client
    bool m_isConnected;

    // Needed to monitor the status of the chat
    bool m_isChatting;

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

    void setErrorMessage(const std::string & msg) { m_errorMsg = msg; }
    std::string getInfoMessage() const { return m_errorMsg; }

    void setConnected() { m_isConnected = true; }
    void setDisconnected() { m_isConnected = false; }
    bool isConnected() { return m_isConnected; }

    // Will be managed by server, to reject or accept the "request to talk"
    void setChatting() { m_isChatting = true; }
    void setNotChatting() { m_isChatting = false; }
    bool isChatting() { return m_isChatting; }

    void setThreadHandler(std::function<void(void)> func) { m_threadHandler = new std::thread(func);}

};


#endif //INTERCOM_CLIENT_H
