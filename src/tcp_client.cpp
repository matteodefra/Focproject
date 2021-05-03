#include "../include/tcp_client.h"
#include "../include/util.h"
#include "../include/client.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

// Connect the client to the server by passing the IP address of the server and the port
// Returns a pipe_ret_t instance

pipe_ret_t TcpClient::connectTo(const std::string & address, int port) {
    m_sockfd = 0;
    pipe_ret_t ret;

    m_sockfd = socket(AF_INET , SOCK_STREAM , 0);
    if (m_sockfd == -1) { //socket failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }

    int inetSuccess = inet_aton(address.c_str(), &m_server.sin_addr); //returns non-zero if the address is a valid one, 
                                                                      //and it returns zero if the address is invalid.

    if(!inetSuccess) { // inet_addr failed to parse address
        // if hostname is not in IP strings and dots format, try resolve it
        struct hostent *host;
        struct in_addr **addrList;
        if ( (host = gethostbyname( address.c_str() ) ) == NULL){
            ret.success = false;
            ret.msg = "Failed to resolve hostname";
            return ret;
        }
        addrList = (struct in_addr **) host->h_addr_list;
        m_server.sin_addr = *addrList[0];
    }

    m_server.sin_family = AF_INET;
    m_server.sin_port = htons( port );

    int connectRet = connect(m_sockfd , (struct sockaddr *)&m_server , sizeof(m_server));

    if (connectRet == -1) { //connect failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }

    m_receiveTask = new std::thread(&TcpClient::ReceiveTask, this);
    ret.success = true;
    return ret;
}


/**
 * Encrypt the message with AES-128 bit in CBC mode.
 * Return a struct containing message and length 
 */
// encdecMsg encrypt() {
//     return;
// }

/**
 * This function will need to implement secure symmetric communication 
 * through the symmetric key negotiated in the first part
 */
pipe_ret_t TcpClient::sendMsg(const char * msg, size_t size) {
    pipe_ret_t ret;
    // We must create here before the secure message
    // Read .pem key and create secure msg
    // AES-128 CBC bit
    // encdecMsg encrypt();


    // Change name accordingly
    int numBytesSent = send(m_sockfd, msg, size, 0);
    if (numBytesSent < 0 ) { // send failed
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

void TcpClient::subscribe(const client_observer_t & observer) {
    m_subscribers.push_back(observer);
}

void TcpClient::unsubscribeAll() {
    m_subscribers.clear();
}

/*
 * Publish incoming client message to observer.
 * Observers get only messages that originated
 * from clients with IP address identical to
 * the specific observer requested IP
 */
void TcpClient::publishServerMsg(const char * msg, size_t msgSize) {
    for (uint i=0; i<m_subscribers.size(); i++) {
        if (m_subscribers[i].incoming_packet_func != NULL) {
            (*m_subscribers[i].incoming_packet_func)(msg, msgSize);
        }
    }
}

/*
 * Publish client disconnection to observer.
 * Observers get only notify about clients
 * with IP address identical to the specific
 * observer requested IP
 */
void TcpClient::publishServerDisconnected(const pipe_ret_t & ret) {
    for (uint i=0; i<m_subscribers.size(); i++) {
        if (m_subscribers[i].disconnected_func != NULL) {
            (*m_subscribers[i].disconnected_func)(ret);
        }
    }
}

/**
 * First function that need to be implemented: the starting client,
 * after connection, will first authenticate, with a public key preinstalled 
 * on the server. The private key will be inside each client protected by a
 * password. After the autenthication, if everything went well client and 
 * server will negotiate a session key to use for their communication
 */
void TcpClient::authenticateThroughServer() {
    // Send public key, authentication using certificates
    // Then symmetric session key negotiation via elliptic curve diffie hellman
    return;
}

/**
 * This function will ask server for all connected clients.
 * Need to implement secure communication through symmetric key
 */
void TcpClient::displayAllClients() {
    return;
}

/**
 * Util function to decrypt server message
 * 
 * @param encMsg encoded message arrived from server
 * @param encMsgLen length of the encoded message
 * 
 * Decrypt the encMsg and return a struct, containing the decrypted message
 * and the length of the decrypted message.
 * If some error occurs, the message is discarded
 */
encdecMsg decrypt(unsigned char* encMsg, int encMsgLen) {
    int ret;

    // Setup of the encryption part
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    int iv_len = EVP_CIPHER_iv_length(cipher);
    int block_size = EVP_CIPHER_block_size(cipher);

    /**
     * Recover the symmetric key between client and server. At this time, the corresponding 
     * shared secret is already inside client memory and server too
     */
    unsigned char *key = (unsigned char *)"0123456789012345";

    // EVP_PKEY* sharedSecret = getServerClientSharedSecret();
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    RAND_poll();
    ret = RAND_bytes((unsigned char*)&iv[0],iv_len);
    if (ret != 1) {
        DECRYPT_ERROR;
    }

    int dec_buffer_size = encMsgLen + block_size;
    unsigned char *cphr_buf = (unsigned char *)malloc(dec_buffer_size);

    EVP_CIPHER_CTX *dec_ctx;
    dec_ctx = EVP_CIPHER_CTX_new();
    if (!dec_ctx) {
        DECRYPT_ERROR;
    }
    // ret = EVP_DecryptInit(dec_ctx,cipher,sharedSecret,iv);
    ret = EVP_DecryptInit(dec_ctx,cipher,key,iv);
    if (ret != 1) {
        DECRYPT_ERROR;
    }

    int update_len = 0;
    int total_len = 0;

    while ((EVP_DecryptUpdate(dec_ctx,cphr_buf,&update_len,encMsg,encMsgLen)) != 1) {
        DECRYPT_ERROR;
    }
    total_len += update_len;

    ret = EVP_DecryptFinal(dec_ctx,cphr_buf + total_len,&update_len);
    if (ret != 1) {
        DECRYPT_ERROR;
    }
    total_len += update_len;
    int cphr_size = total_len;

    // Free decryption memory
    EVP_CIPHER_CTX_free(dec_ctx);
    
    encdecMsg decodedMsg;
    std::string decodedString( reinterpret_cast<char const*>(cphr_buf), cphr_size ) ;
    decodedMsg.msg = decodedString;
    decodedMsg.size = cphr_size;

    free(cphr_buf);
    free(iv); //?

    return decodedMsg;
}   

/*
 * Receive server packets, and notify user
 */
void TcpClient::ReceiveTask() {

    // Whenever client thread starts, the first thing client will do is the authentication
    authenticateThroughServer();

    while(!stop) {
        char msg[MAX_PACKET_SIZE];
        int numOfBytesReceived = recv(m_sockfd, msg, MAX_PACKET_SIZE, 0);

        if(numOfBytesReceived < 1) {
            pipe_ret_t ret;
            ret.success = false;
            stop = true;
            if (numOfBytesReceived == 0) { //server closed connection
                ret.msg = "Server closed connection";
            } else {
                ret.msg = strerror(errno);
            }
            publishServerDisconnected(ret);
            finish();
            break;
        } else {
            // Decrypt arrived message
            encdecMsg receivedMsg = decrypt((unsigned char*)msg, numOfBytesReceived);

            // Based on message received, we need to perform some action
            publishServerMsg(receivedMsg.msg.c_str(), receivedMsg.size);
        }
    }
}

pipe_ret_t TcpClient::finish(){
    stop = true;
    terminateReceiveThread();
    pipe_ret_t ret;
    if (close(m_sockfd) == -1) { // close failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }
    ret.success = true;
    return ret;
}

void TcpClient::terminateReceiveThread() {
    if (m_receiveTask != nullptr) {
        m_receiveTask->detach();
        delete m_receiveTask;
        m_receiveTask = nullptr;
    }
}

TcpClient::~TcpClient() {
    terminateReceiveThread();
}
