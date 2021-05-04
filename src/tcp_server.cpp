#include "../include/tcp_server.h"
#include "../include/util.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;

void TcpServer::subscribe(const server_observer_t & observer) {
    m_subscribers.push_back(observer);
}

void TcpServer::unsubscribeAll() {
    m_subscribers.clear();
}

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
 * Util function to decrypt server message
 * 
 * @param encMsg encoded message arrived from server
 * @param encMsgLen length of the encoded message
 * 
 * Decrypt the encMsg and return a struct, containing the decrypted message
 * and the length of the decrypted message.
 * If some error occurs, the message is discarded
 */
encdecMsg decrypt(unsigned char* encMsg, size_t encMsgLen) {
    int ret;

    cout << encMsgLen << endl;

    BIO_dump_fp(stdout,(const char *)encMsg,encMsgLen);

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

    if (encMsgLen > INT_MAX - block_size) {
        cout << "qui1" << endl;
        DECRYPT_ERROR;
    }

    size_t dec_buffer_size = encMsgLen + block_size;
    unsigned char *plain_buf = (unsigned char *)malloc(dec_buffer_size);

    EVP_CIPHER_CTX *dec_ctx;
    dec_ctx = EVP_CIPHER_CTX_new();
    if (!dec_ctx) {
        cout << "qui2" << endl;
        DECRYPT_ERROR;
    }
    // ret = EVP_DecryptInit(dec_ctx,cipher,sharedSecret,iv);
    ret = EVP_DecryptInit(dec_ctx,cipher,key,NULL);
    if (ret != 1) {
        cout << "qui3" << endl;
        DECRYPT_ERROR;
    }

    int update_len = 0;
    int total_len = 0;

    // while(1){
        int decryptUpdate_ret = EVP_DecryptUpdate(dec_ctx, (unsigned char *)plain_buf + total_len, &update_len, (unsigned char *)encMsg + total_len, encMsgLen);

        if(decryptUpdate_ret != 1) {
	    	std::cerr << "Error: EncryptUpdate";
	    	exit(-1);
	    }

    //     cout << "Chiamata qui" << endl;
    //     total_len += update_len;
    //     if( encMsgLen - total_len < block_size ){
    //      break;
    //     }
    // }

    ret = EVP_DecryptFinal(dec_ctx,(unsigned char *)plain_buf + total_len,&update_len);
    ERR_print_errors_fp(stderr);
    cout << ret << endl;
    if (ret != 1) {
        cout << "qui4" << endl;
        DECRYPT_ERROR;
    }
    total_len += update_len;
    int cphr_size = total_len;

    // Free decryption memory
    EVP_CIPHER_CTX_free(dec_ctx);
    
    encdecMsg decodedMsg;
    decodedMsg.msg = (char*)plain_buf;
    decodedMsg.msg_size = cphr_size;

    cout << decodedMsg.msg << endl;

    free(plain_buf);
    free(iv); //?

    return decodedMsg;
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

            BIO_dump_fp(stdout,(const char *)msg,numOfBytesReceived);


            // Decrypt received message with AES-128 bit CBC
            encdecMsg decryptedMessage = decrypt((unsigned char*)msg,numOfBytesReceived);

            // Discretize based on the received message
            publishClientMsg(*client, decryptedMessage.msg.c_str(), decryptedMessage.msg_size);
        }
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


encdecMsg encrypt(const char * msg, size_t size) {

    encdecMsg ret;

    //conversion from char to unsigned char
    unsigned char* clear_buf = (unsigned char*)malloc(size); 
    for(int i = 0; i < size; i++){
        clear_buf[i] = static_cast<unsigned char>(msg[i]);
    }

    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
	int iv_len = EVP_CIPHER_iv_length(cipher);
	int block_size = EVP_CIPHER_block_size(cipher);

    unsigned char *key = (unsigned char *)"0123456789012345"; //change with the shared key
	unsigned char *iv = (unsigned char *)malloc(iv_len);

    RAND_poll(); //seed generation

    int rand_ret = RAND_bytes((unsigned char*)&iv[0], iv_len);

    if(rand_ret != 1) { //rand in the error
		std::cerr << "Error: RAND";
		exit(-1);
	}

    if(size > INT_MAX - block_size) { //int overflow
		std::cerr << "Error: int overflow";
		exit(-1);
	}

    size_t enc_buffer_size = size + block_size; //buffer size for ciphertxt

    unsigned char* cipher_buf = (unsigned char*)malloc(enc_buffer_size);
    
    if(!cipher_buf) {
		std::cerr << "Error: malloc";
		exit(-1);
	}

    //Contest creation

    EVP_CIPHER_CTX *ctx;

	ctx = EVP_CIPHER_CTX_new();

	if(!ctx) { //error in the context declaration
		std::cerr << "Error: ctx declaration";
		exit(-1);
	}

	int encryptInit_ret = EVP_EncryptInit(ctx, cipher, key, iv);

	if(encryptInit_ret != 1) {
		std::cerr << "Error: EncryptInit";
		exit(-1);
	}

	int update_len = 0;
	int total_len = 0;

    // while(1){
        int encyptUpdate_ret = EVP_EncryptUpdate(ctx, (unsigned char *)cipher_buf + total_len, &update_len, (unsigned char *)clear_buf + total_len, size);

        if(encyptUpdate_ret != 1) {
	    	std::cerr << "Error: EncryptUpdate";
	    	exit(-1);
	    }

    //     total_len += update_len;
    //     if( size - total_len < block_size ){
    //      break;
    //     }
    // }

    int encryptFinal_ret = EVP_EncryptFinal(ctx, (unsigned char *)cipher_buf + total_len, &update_len);
	
    if(encryptFinal_ret != 1) {
		std::cerr << "Error: EncryptFinal";
		exit(-1);
	}

	total_len += update_len;
	size_t cipher_size = total_len;

    EVP_CIPHER_CTX_free(ctx);
    free(clear_buf);

    ret.msg = (char*)cipher_buf;
    ret.msg_size = cipher_size;
    ret.iv = (char*)iv;
    ret.iv_size = iv_len;

    free(cipher_buf);
    free(iv);

    return ret;
}



/*
 * Send message to specific client (determined by client IP address).
 * Return true if message was sent successfully
 */
pipe_ret_t TcpServer::sendToClient(const Client & client, const char * msg, size_t size){
    pipe_ret_t ret;
    encdecMsg new_encdecMsg;

    // Encrypt message with AES128 bit- CBC mode
    // TODO
    new_encdecMsg = encrypt(msg,size);

    char * enc_msg = &new_encdecMsg.msg[0];


    int numBytesSent = send(client.getFileDescriptor(), enc_msg, new_encdecMsg.msg_size, 0);
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
