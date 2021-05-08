#include "../include/tcp_server.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;

/**
 * Populate the subscribers list
 */
void TcpServer::subscribe(const server_observer_t & observer) {
    m_subscribers.push_back(observer);
}

/**
 * Clear the subscribers list
 */
void TcpServer::unsubscribeAll() {
    m_subscribers.clear();
}

/**
 * Print list of clients connected
 */
void TcpServer::printClients() {
    for (uint i=0; i<m_clients.size(); i++) {
        std::string connected = m_clients[i].isConnected() ? "True" : "False";
        std::cout << "-----------------\n" <<
                  "IP address: " << m_clients[i].getIp() << std::endl <<
                  "Connected?: " << connected << std::endl <<
                  "Socket FD: " << m_clients[i].getFileDescriptor() << std::endl <<
                  "Message: " << m_clients[i].getInfoMessage().c_str() << std::endl;
    }
}


/**
 * Server will receive authentication from the client and will check its public key 
 * (which is stored from start as guideline). Than will communicate its certificate 
 * authority in order to prove its affidability. Then symmetric key is negotiated
 */
void authenticateServer() {
    // send certificate
    // negotiate elliptic curve diffie hellman key
    return;
}

/**
 * Utility function to handle OPENSSL errors
 */
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


/**
 * Util function to decrypt server message
 * 
 * @param ciphertext the ciphertext to decrypt
 * @param ciphertext_len length of the message to decrypt
 * @param aad additional data to add in the message
 * @param aad_len length of the aad portion
 * @param tag the nonce to append or prepend to the string
 * @param key the secret shared key
 * @param iv the initialization vector contained in the message
 * @param iv_len the length of the iv
 * @param plaintext pointer to the variable where we store the decrypted text
 * 
 * Decrypt the ciphertext and return its length, the buffer of the plaintext is passed as pointer. 
 * If some error occurs, the message is discarded
 */
int gcm_decrypt(unsigned char *ciphertext, size_t ciphertext_len, 
                unsigned char *aad, size_t aad_len, 
                unsigned char *tag,
                unsigned char *key, unsigned char *iv, 
                size_t iv_len, 
                unsigned char *plaintext) {

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len = 0;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        std::cout<<" Error in creating the context for encryption"<<std::endl;
        handleErrors();
    }
    // Initialise the encryption operation.
    if(1 != EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv)) {
        std::cout<<"Error in Initialising the encryption operation"<<std::endl;
        handleErrors();
    }
    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
        std::cout<<" Error in providing AAD"<<std::endl;
        handleErrors();
    }


    while ( (plaintext_len < (ciphertext_len - 8)) && ciphertext_len > 8) {    
        cout << "Entra nel loop?" << endl;
        if(1 != EVP_DecryptUpdate(ctx, plaintext + plaintext_len, &len, ciphertext + plaintext_len, 8)){
            std::cout<<"Error in performing encryption"<<std::endl;
            handleErrors();
        }
        plaintext_len += len;
        ciphertext_len -= len;
    }

    if(1 != EVP_DecryptUpdate(ctx, plaintext + plaintext_len, &len, ciphertext + plaintext_len, ciphertext_len)){
        std::cout<<"Error in performing encryption"<<std::endl;
        handleErrors();
    }
    plaintext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)){
        std::cout<<"Error in retrieving the tag "<<std::endl;
        handleErrors();
    }

    //Finalize Encryption
    if(1 != EVP_DecryptFinal(ctx, plaintext + plaintext_len, &len)){
        std::cout<<"Error in finalizing encryption"<<std::endl;
        handleErrors();
    }
    plaintext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}


/*
 * Receive client packets, and notify user
 */
void TcpServer::receiveTask(/*TcpServer *context*/) {

    Client * client = &m_clients.back();
    
    // authenticateServer();

    // Public key?

    while(client->isConnected()) {
        char msg[MAX_PACKET_SIZE];
        int numOfBytesReceived = recv(client->getFileDescriptor(), msg, MAX_PACKET_SIZE, 0);

        cout << "Bytes received: "<< numOfBytesReceived << endl;

        if(numOfBytesReceived < 1) {
            client->setDisconnected();
            if (numOfBytesReceived == 0) { //client closed connection
                client->setErrorMessage("Client closed connection");
                //printf("client closed");
            } else {
                client->setErrorMessage(strerror(errno));
            }
            close(client->getFileDescriptor());
            publishClientDisconnected(*client);
            deleteClient(*client);
            break;
        } else {
        
            cout << "Server, starting decryption settings..." << endl;

            unsigned char key_gcm[] = "1234567890123456";

            int pos = 0;
            // retrieve IV
            unsigned char iv_gcm[12];
            memcpy(iv_gcm,msg+pos,12);
            pos += 12;

            // retrieve AAD
            unsigned char AAD[12];
            memcpy(AAD, msg+pos,12);
            pos += 12;

            // retrieve encrypted data
            size_t encrypted_len = numOfBytesReceived - 16 - 12 - 12;
            unsigned char encryptedData[encrypted_len];
            memcpy(encryptedData,msg+pos,encrypted_len);
            pos += encrypted_len;

            // retrieve tag
            size_t tag_len = 16;
            unsigned char tag[tag_len];
            memcpy(tag, msg+pos, tag_len);
            pos += tag_len;

            unsigned char *plaintext_buffer = (unsigned char*)malloc(encrypted_len);

            // Decrypt received message with AES-128 bit GCM, store result in plaintext_buffer
            int decrypted_len = gcm_decrypt(encryptedData,encrypted_len,AAD,12,tag,key_gcm,iv_gcm,12,plaintext_buffer);

            cout << "Server, decrypted message: " << plaintext_buffer << endl;


            // Process client request 
            // processRequest(*client,plaintext_buffer);

            // Simple server answer: get word from input and send an answer back
            string send;
            getline(cin,send);
            pipe_ret_t res = sendToClient(*client,send.c_str(),send.size());
            cout << "Server, message sent, succes: " << res.success << endl;
        }

    }
}

/**
 * Utility function to store in the receivingClient object the information about the 
 * requestingClient istance
 */
void TcpServer::storeRequestingInfo(Client &receivingClient,Client &requestingClient) {
    receivingClient.setChattingClientInfo(requestingClient.getIp(),requestingClient.getFileDescriptor());
}


/**
 * Return the client istance to whom send the request. If client is not logged or not connected,
 * return the requesting client itself
 */
Client TcpServer::sendRequest(Client &client, string message) {
    string requestingName = client.getClientName();
    char *pointer = strtok((char*)message.c_str()," ");

    pointer = strtok(NULL," ");
    // Now pointer contains the name of the answerer
    for (auto&s : m_clients) {
        if (strcmp(s.getClientName().c_str(),pointer)==0) {
            // Found answerer
            // Create message and send response
            return s;
        }
    }
    // if no client found, then answered is not connected or maybe still not logged
    return client;
}


/**
 * Login function: memorize client name and send back an OK ack in order to manage list of connected clients
 */
string TcpServer::loginClient(Client &client, string message) {
    char *pointer = strtok((char*)message.c_str()," ");
    
    pointer = strtok(NULL," ");
    // Now pointer should contain the username
    // username could be tainted, pay attention
    // check before if username has already been taken
    // checkUsername

    client.setClientName(pointer);

    string response = "Login successful, welcome to the chatting platform!";
    return response;
}


/**
 * Concatenate each client's connected name into a string, to form a dummy list to 
 * send to the client. Need to be added
 */
string TcpServer::createList(Client &client, string message) {
    string allClients;
    allClients = "[";
    for (auto&s : m_clients) {
        string clientName = s.getClientName();
        allClients = allClients + " " + clientName;
    }
    allClients = allClients + " ]";
    
    return allClients;
}


/**
 * Utility function: used to recover, from the receiving client, the instance of the requesting client
 * inside the list of connected client. If client is found, the instance is returned. If client is not found, 
 * (because e.g. of a disconnection) the receiving client istance itself is returned.
 */
Client TcpServer::getClient(Client &client) {
    string chattinIp = client.getChattingClientIp();
    int chattinSocket = client.getChattingClientSocket();

    for (auto&s : m_clients) {
        if (s.getIp() == chattinIp && s.getFileDescriptor() == chattinSocket) return s;
    }
    return client;
}


/**
 * Util function used by server to dispatch the client request. Need to be implemented
 */
void TcpServer::processRequest(Client &client,string decryptedMessage) {
    string request = decryptedMessage;
    
    pipe_ret_t ret;

    if (strncmp(request.c_str(),":LIST",5) == 0) {
        if (!client.isAuthenticated()) {
            // Cannot start normal flow until authentication is estabilished
        }
        string clientsList = createList(client,request);
        ret = sendToClient(client,clientsList.c_str(),strlen(clientsList.c_str()));
    }
    else if (strncmp(request.c_str(),":REQ",4) == 0) {
        if (!client.isConnected()) {
            // Cannot start a request-to-talk until a login is provided
        }
        if (!client.isAuthenticated()) {
            // Cannot start normal flow until authentication is estabilished
        }
        if (client.isChatting()) {
            // Cannot instantiate a Request to Talk if are already talking
        }

        Client receivingClient = sendRequest(client,request);
        if (receivingClient == client) {
            // Client is not connected or not logged
            string response = "Client not connected or not logged";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        }
        else {
            // Client is connected: send message
            string response = "Request-to-talk from " + client.getClientName() + "; Do you want to accept?";
            storeRequestingInfo(receivingClient,client);
            ret = sendToClient(receivingClient,response.c_str(),strlen(response.c_str()));
        }
    }
    else if (strncmp(request.c_str(),":LOGIN",6) == 0) {
        if (!client.isAuthenticated()) {
            // Cannot start normal flow until authentication is estabilished
        }
        // A must function: each client must furnish a login name
        string response = loginClient(client,request);
        ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
    }
    else if (strncmp(request.c_str(),":ACCEPT",7) ==0 ) {
        // Recover the requesting client from the receiver client istance, and forward the ACCEPT message
        Client requestingClient = getClient(client);
        if (requestingClient == client) {
            // The requesting client probably disconnected
            string response = "The requesting client is disconnected";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        }
        else {
            // Simply forward the ":ACCEPT to the requesting client"  
            ret = sendToClient(requestingClient,request.c_str(),strlen(request.c_str()));
        }
    }
    else if (strncmp(request.c_str(),":DENY",5) ==0 ) {
        // Recover the requesting client from the receiver client istance, and forward the DENY message
        Client requestingClient = getClient(client);
        if (requestingClient == client) {
            // The requesting client probably disconnected
            string response = "The requesting client is disconnected";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        }
        else {
            // Simply forward the ":DENY to the requesting client"
            ret = sendToClient(requestingClient,request.c_str(),strlen(request.c_str()));
        }
    }
    else {
        string response = "Message format not recognized, type :HELP to get more information";
        ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
    }
}


/*
 * Erase client from clients vector.
 * If client isn't in the vector, return false. Return
 * true if it is.
 */
bool TcpServer::deleteClient(Client & client) {
    int clientIndex = -1;
    for (uint i=0; i<m_clients.size(); i++) {
        if (m_clients[i] == client) {
            clientIndex = i;
            break;
        }
    }
    if (clientIndex > -1) {
        m_clients.erase(m_clients.begin() + clientIndex);
        return true;
    }
    return false;
}


/*
 * Publish incoming client message to observer.
 * Observers get only messages that originated
 * from clients with IP address identical to
 * the specific observer requested IP
 */
void TcpServer::publishClientMsg(const Client & client, const char * msg, size_t msgSize) {
    for (uint i=0; i<m_subscribers.size(); i++) {
        if (m_subscribers[i].wantedIp == client.getIp() || m_subscribers[i].wantedIp.empty()) {
            if (m_subscribers[i].incoming_packet_func != NULL) {
                (*m_subscribers[i].incoming_packet_func)(client, msg, msgSize);
            }
        }
    }
}


/*
 * Publish client disconnection to observer.
 * Observers get only notify about clients
 * with IP address identical to the specific
 * observer requested IP
 */
void TcpServer::publishClientDisconnected(const Client & client) {
    for (uint i=0; i<m_subscribers.size(); i++) {
        if (m_subscribers[i].wantedIp == client.getIp()) {
            if (m_subscribers[i].disconnected_func != NULL) {
                (*m_subscribers[i].disconnected_func)(client);
            }
        }
    }
}


/*
 * Bind port and start listening
 * Return tcp_ret_t
 */
pipe_ret_t TcpServer::start(int port) {
    m_sockfd = 0;
    m_clients.reserve(10);
    m_subscribers.reserve(10);
    pipe_ret_t ret;

    m_sockfd = socket(AF_INET,SOCK_STREAM,0);
    if (m_sockfd == -1) { //socket failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }
    // set socket for reuse (otherwise might have to wait 4 minutes every time socket is closed)
    int option = 1;
    setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    memset(&m_serverAddress, 0, sizeof(m_serverAddress));
    m_serverAddress.sin_family = AF_INET;
    m_serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    m_serverAddress.sin_port = htons(port);

    int bindSuccess = bind(m_sockfd, (struct sockaddr *)&m_serverAddress, sizeof(m_serverAddress));
    if (bindSuccess == -1) { // bind failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }
    const int clientsQueueSize = 5;
    int listenSuccess = listen(m_sockfd, clientsQueueSize);
    if (listenSuccess == -1) { // listen failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }
    ret.success = true;
    return ret;
}


/*
 * Accept and handle new client socket. To handle multiple clients, user must
 * call this function in a loop to enable the acceptance of more than one.
 * If timeout argument equal 0, this function is executed in blocking mode.
 * If timeout argument is > 0 then this function is executed in non-blocking
 * mode (async) and will quit after timeout seconds if no client tried to connect.
 * Return accepted client
 */
Client TcpServer::acceptClient(uint timeout) {
    socklen_t sosize  = sizeof(m_clientAddress);
    Client newClient;

    if (timeout > 0) {
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        FD_ZERO(&m_fds);
        FD_SET(m_sockfd, &m_fds);
        int selectRet = select(m_sockfd + 1, &m_fds, NULL, NULL, &tv);
        if (selectRet == -1) { // select failed
            newClient.setErrorMessage(strerror(errno));
            return newClient;
        } else if (selectRet == 0) { // timeout
            newClient.setErrorMessage("Timeout waiting for client");
            return newClient;
        } else if (!FD_ISSET(m_sockfd, &m_fds)) { // no new client
            newClient.setErrorMessage("File descriptor is not set");
            return newClient;
        }
    }

    int file_descriptor = accept(m_sockfd, (struct sockaddr*)&m_clientAddress, &sosize);
    if (file_descriptor == -1) { // accept failed
        newClient.setErrorMessage(strerror(errno));
        return newClient;
    }

    // Public key?

    newClient.setFileDescriptor(file_descriptor);
    newClient.setConnected();
    newClient.setIp(inet_ntoa(m_clientAddress.sin_addr));
    m_clients.push_back(newClient);
    m_clients.back().setThreadHandler(std::bind(&TcpServer::receiveTask, this));

    return newClient;
}


/*
 * Send message to all connected clients.
 * Return true if message was sent successfully to all clients
 */
pipe_ret_t TcpServer::sendToAllClients(const char * msg, size_t size) {
    pipe_ret_t ret;
    for (uint i=0; i<m_clients.size(); i++) {
        ret = sendToClient(m_clients[i], msg, size);
        if (!ret.success) {
            return ret;
        }
    }
    ret.success = true;
    return ret;
}


/**
 * gcm_encrypt: encrypt a message in aes-128 gcm mode
 * 
 * @param plaintext the message to encrypt
 * @param plaintext_len the length of the message to encrypt
 * @param aad additional data to add to the message
 * @param aad_len the length of the additional data portion
 * @param iv the random initialization vector prepend to the message
 * @param iv_len the length of the initialization vector
 * @param ciphertext the pointer to variable where to store the encrypted message
 * @param tag the nonce appended to the message
 * 
 * The function encrypt create a message in AES 128 bit mode GCM, cycling if the message size is 
 * greater than AES block size. Return the length of the encrypted text
 */ 
int gcm_encrypt(unsigned char *plaintext, size_t plaintext_len, 
                unsigned char *aad, size_t aad_len, 
                unsigned char *key,
                unsigned char *iv, size_t iv_len, 
                unsigned char *ciphertext, 
                unsigned char *tag) {

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len = 0;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        std::cout<<" Error in creating the context for encryption"<<std::endl;
        handleErrors();
    }
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv)) {
        std::cout<<"Error in Initialising the encryption operation"<<std::endl;
        handleErrors();
    }
    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){
        std::cout<<" Error in providing AAD"<<std::endl;
        handleErrors();
    }


    while ( (ciphertext_len < (plaintext_len-8)) && plaintext_len > 8) {
        cout << "Entra nel loop?" << endl;
        if(1 != EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext + ciphertext_len, 8)){
            std::cout<<"Error in performing encryption"<<std::endl;
            handleErrors();
        }
        ciphertext_len += len;
        plaintext_len -= len;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext + ciphertext_len, plaintext_len)){
        std::cout<<"Error in performing encryption"<<std::endl;
        handleErrors();
    }
    ciphertext_len += len;
    
    //Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext + ciphertext_len, &len)){
        std::cout<<"Error in finalizing encryption"<<std::endl;
        handleErrors();
    }
    ciphertext_len += len;
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)){
        std::cout<<"Error in retrieving the tag "<<std::endl;
        handleErrors();
    }
    /* Clean up */

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


/*
 * Send message to specific client (determined by client IP address).
 * Return true if message was sent successfully
 */
pipe_ret_t TcpServer::sendToClient(const Client & client, const char * msg, size_t size){
    pipe_ret_t ret;

    // Also this first part could be included in a utility function
    unsigned char msg2[size];
    strcpy((char*)msg2,msg);

    unsigned char key_gcm[] = "1234567890123456";
    unsigned char iv_gcm[] = "123456780912";
    unsigned char *cphr_buf;
    unsigned char *tag_buf;
    int cphr_len;
    int tag_len;
    int pt_len = strlen(msg);

    cphr_buf = (unsigned char*)malloc(size);
    tag_buf = (unsigned char*)malloc(16);
    cphr_len = gcm_encrypt(msg2,pt_len,iv_gcm,12,key_gcm,iv_gcm,12,cphr_buf,tag_buf);

    auto *buffer = new unsigned char[12/*aad_len*/+pt_len+16/*tag_len*/+12/*iv_len*/];

    int pos = 0;
  
    // copy iv
    memcpy(buffer+pos, iv_gcm, 12);
    pos += 12;
    // delete [] iv_gcm;

    //copio aad
    memcpy((buffer+pos), iv_gcm, 12);
    pos += 12;

    //copio encrypted
    memcpy((buffer+pos), cphr_buf, cphr_len);
    pos += pt_len;
    delete[] cphr_buf;

    //copio tag
    memcpy((buffer+pos), tag_buf, 16);
    pos += 16;
    delete [] tag_buf;

    cout << "Server, dumping the encrypted payload: " << endl;
    BIO_dump_fp(stdout,(char*)buffer,strlen((char*)buffer));
    cout << "Total buffer dimension: "<< strlen((char*)buffer) << endl;

    int numBytesSent = send(client.getFileDescriptor(), buffer, 12/*aad_len*/+pt_len+16/*tag_len*/+12/*iv_len*/, 0);
    if (numBytesSent < 0) { // send failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }
    if ((uint)numBytesSent < size) { // not all bytes were sent
        ret.success = false;
        char msg[100];
        sprintf(msg, "Only %d bytes out of %lu was sent to client", numBytesSent, size);
        ret.msg = msg;
        return ret;
    }
    ret.success = true;
    return ret;
}

/**
 * Send the request to talk to the other party
 */
// pipe_ret_t TcpServer::communicateRequest(const Client & client, const char * msg, size_t size){
//     Get Client object instance from username
//     Client c = getClient(std::string username);
//     return;
// }
/**
 * Use digital envelope
 */ 


/*
 * Close server and clients resources.
 * Return true is success, false otherwise
 */
pipe_ret_t TcpServer::finish() {
    pipe_ret_t ret;
    for (uint i=0; i<m_clients.size(); i++) {
        m_clients[i].setDisconnected();
        if (close(m_clients[i].getFileDescriptor()) == -1) { // close failed
            ret.success = false;
            ret.msg = strerror(errno);
            return ret;
        }
    }
    if (close(m_sockfd) == -1) { // close failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }
    m_clients.clear();
    ret.success = true;
    return ret;
}
