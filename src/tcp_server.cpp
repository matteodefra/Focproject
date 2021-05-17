#include "../include/tcp_server.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <fstream>
#include <assert.h>

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

unsigned char *pem_serialize_certificate(X509 *cert, size_t *len)
{
	assert(cert && len);
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio) {
		handleErrors();
		return NULL;
	}
	if (PEM_write_bio_X509(bio, cert) != 1) {
		handleErrors();
		BIO_free(bio);
		return NULL;
	}
	char *buf;
	*len = BIO_get_mem_data(bio, &buf);
	if (*len <= 0 || !buf) {
		handleErrors();
		BIO_free(bio);
		return NULL;
	}
	unsigned char *certificate = (unsigned char*)malloc(*len);
	if (!certificate)
		handleErrors();
	memcpy(certificate, buf, *len);
	BIO_free(bio);
	return certificate;
}


unsigned char *pem_serialize_pubkey(EVP_PKEY *key, size_t *len)
{
	assert(key && len);
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio) {
		handleErrors();
		return NULL;
	}
	if (PEM_write_bio_PUBKEY(bio, key) != 1) {
		handleErrors();
		BIO_free(bio);
		return NULL;
	}
	char *buf;
	*len = BIO_get_mem_data(bio, &buf);
	if (*len <= 0 || !buf) {
		handleErrors();
		BIO_free(bio);
		return NULL;
	}
	unsigned char *pubkey = (unsigned char*)malloc(*len);
	if (!pubkey)
		handleErrors();
	memcpy(pubkey, buf, *len);
	BIO_free(bio);
	return pubkey;
}

EVP_PKEY *pem_deserialize_pubkey(unsigned char *key, size_t len)
{
	assert(key);
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio) {
		handleErrors();
		return NULL;
	}
	if (BIO_write(bio, key, len) != (int)len) {
		handleErrors();
		BIO_free(bio);
		return NULL;
	}
	EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!pubkey)
		handleErrors();
	BIO_free(bio);
	return pubkey;
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
        //cout << "Entra nel loop?" << endl;
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

            if (client->isChatting()) {
                // Client send the message to the other party
                // Get the client socket from the client istance and forward it
                Client &receiver = getClient(*client);

                sendToClient(receiver,msg,numOfBytesReceived);
            }
        
            else {
                cout<<"msg:"<<endl;
                cout<<msg<<endl;
                if(strncmp(msg,":CERT",5) == 0 || strncmp(msg,":USER",5) == 0){ //These msg are sent in clear during the authentication phase
                    cout << "Enter here? " << msg << endl;
                    processRequest(*client,msg);
                } 
                else{
                    cout << "Server, starting decryption settings..." << endl;

                    // Derive the shared secret
                    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(serverDHPrivKey, NULL);
                    EVP_PKEY_derive_init(ctx_drv);
                    if (1 != EVP_PKEY_derive_set_peer(ctx_drv, client->getClientKey())) {
                        handleErrors();
                    }
                    unsigned char* secret;

                    /* Retrieving shared secret’s length */
                    size_t secretlen;
                    if (1 != EVP_PKEY_derive(ctx_drv, NULL, &secretlen)) {
                        handleErrors();
                    }
                    /* Deriving shared secret */
                    secret = (unsigned char*)malloc(secretlen);
                    if (secret == NULL) {
                        handleErrors();
                    }
                    if (1 != EVP_PKEY_derive(ctx_drv, secret, &secretlen)) {
                        handleErrors();
                    }
                    EVP_PKEY_CTX_free(ctx_drv);

                    // We need to derive the hash of the shared secret now
                    unsigned char* digest;
                    unsigned int digestlen;
                    EVP_MD_CTX* digest_ctx;
                    /* Buffer allocation for the digest */
                    digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
                    /* Context allocation */
                    digest_ctx = EVP_MD_CTX_new();

                    /* Hashing (initialization + single update + finalization */
                    EVP_DigestInit(digest_ctx, EVP_sha256());
                    EVP_DigestUpdate(digest_ctx, secret, sizeof(secret));
                    EVP_DigestFinal(digest_ctx, digest, &digestlen);
                    /* Context deallocation */
                    EVP_MD_CTX_free(digest_ctx);

                    // Taking first 128 bits of the digest
                    // Get first 16 bytes of shared secret, to use as key in AES
                    unsigned char *key = (unsigned char*)malloc(16);
                    // for (int i =0; i<16; i++) {
                    //     key[i] = digest[i];
                    // }
                    memcpy(key,digest,16);


                    // unsigned char key_gcm[] = "1234567890123456";

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

                    unsigned char *plaintext_buffer = (unsigned char*)malloc(encrypted_len+1);

                    // Decrypt received message with AES-128 bit GCM, store result in plaintext_buffer
                    int decrypted_len = gcm_decrypt(encryptedData,encrypted_len,AAD,12,tag,key,iv_gcm,12,plaintext_buffer);

                    plaintext_buffer[encrypted_len] = '\0';

                    cout << "Server, decrypted message: " << plaintext_buffer << endl;

                    // Process client request 
                    processRequest(*client,(char*)plaintext_buffer);
                    free(plaintext_buffer);
                }
                

            }
            
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
Client& TcpServer::sendRequest(Client &client, string message) {
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
 *  check if the username specified as argument is already registered to the service
 *  return true if the username is not present, false otherwise
 */ 

bool checkUsername(string username){

    ifstream myfile;
    myfile.open ("./AddOn/users.txt");
    if (!myfile.is_open()) {
      cout<<"ERROR: File open"<<endl;
      return false;
    }
    string user, password;
    while (myfile >> user >> password){
        if(user.compare(username) == 0) return false; 
    }   
    myfile.close();

    return true;
  
}

/**
 * Insert the credentials of the new registered user in a file in the format "username password"
 * 
 */

bool insertCredentials(string username, string psw){
  ofstream myfile;
  myfile.open ("./AddOn/users.txt", ios::app);
  if (!myfile.is_open()) {
      cout<<"ERROR: File open"<<endl;
      return false;
  }
  myfile << username << " "<< psw<<endl;
  myfile.close();
  return true;
}

/**
 * Register function: check if there is another user with that username and if not inserts the client credentials into a file
 * Return a string that will be the server answer
 */
string TcpServer::regClient(Client &client, string message) {
    char *pointer = strtok((char*)message.c_str()," ");
    vector<string> credentials; //at.() = username | at.(1) = password
    int counter = 0;

    while (pointer != NULL) { //putting the credentials into vector
        if(counter != 0) credentials.push_back(pointer);
        pointer = strtok(NULL," "); 
        counter++;
    }

    bool duplicate = checkUsername(credentials.at(0)); //TODO: Se chiamata senza che sia presente il file ritorna errore
    bool inserted = false;

    if(duplicate) inserted = insertCredentials(credentials.at(0), credentials.at(1));

    string answer;
    if(inserted) answer = "User successfully registered!";
        else answer = "We had some problem during the registration phase, probably your username is already in use. Try again.";

    return answer;

}

/**
 * return true if the pair is present, false otherwise
 */

bool checkLogin(string username, string psw){

    ifstream myfile;
    myfile.open ("./AddOn/users.txt");
    if (!myfile.is_open()) {
      cout<<"ERROR: File open"<<endl;
      return false;
    }
    string user, password;
    while (myfile >> user >> password){
        if(user.compare(username) == 0 && password.compare(psw) == 0) return true; 
    }   
    myfile.close();

    return false;
}


/**
 * Login function: memorize client name and send back an OK ack in order to manage list of connected clients
 */
string TcpServer::loginClient(Client &client, string message) {
    char *pointer = strtok((char*)message.c_str()," ");
    vector<string> credentials; //at.() = username | at.(1) = password
    int counter = 0;

    while (pointer != NULL) { //putting the credentials into vector
        if(counter != 0) credentials.push_back(pointer);
        pointer = strtok(NULL," "); 
        counter++;
    }

    bool match = checkLogin(credentials.at(0),credentials.at(1));
    string response;
    if(match) response = "Login successful, welcome to the chatting platform!";
        else response = "An error occured, probably we cannot find a match for your credentials, try again.";

    if (match) {
        client.setClientName(credentials.at(0));
    }

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
Client& TcpServer::getClient(Client &client) {
    string chattinIp = client.getChattingClientIp();
    int chattinSocket = client.getChattingClientSocket();

    for (auto&s : m_clients) {
        if (s.getIp() == chattinIp && s.getFileDescriptor() == chattinSocket) return s;
    }
    return client;
}


/**
 * Recover the public key of clientTwo and create message for clientOne
 */
unsigned char* recoverKey(Client &clientOne,Client &clientTwo) {

    string clientName = clientTwo.getClientName();

    string path = "./AddOn/" + clientName + "_pub.pem";

    FILE *file = fopen(path.c_str(),"r");
    if (!file) {
        handleErrors();
    }

    EVP_PKEY *pubkey = PEM_read_PUBKEY(file,NULL,NULL,NULL);

    size_t keylen;
	unsigned char *key = pem_serialize_pubkey(pubkey, &keylen);

    if (!key) {
        handleErrors();
    }

    int pos = 0;
    auto *buffer = new unsigned char[5+keylen];

    memcpy(buffer+pos,":KEY ",5);
    pos += 5;

    memcpy(buffer+pos,key,keylen);


    return buffer;
}


void setClientPublicKey(Client &client, char *username) {

    string name(username);

    string path = "./AddOn/" + name + "_pub.pem";    


    FILE *file = fopen(path.c_str(),"r");
    if (!file) {
        handleErrors();
    }

    EVP_PKEY *pubkey = PEM_read_PUBKEY(file,NULL,NULL,NULL);
    if (!pubkey) {
        handleErrors();
    }

    client.setClientKey(pubkey);

    cout << "Set also client public key successfully" << endl;
}


/**
 * 
 */

pipe_ret_t TcpServer::checkClientIdentity(Client& client, string msg){

    cout<<"MSG:"<<endl;
    cout<<msg<<endl;

    pipe_ret_t ret;

    //Retrieve username from msg

    char *pointer = strtok((char*)msg.c_str()," ");
    char* username;
    vector<string> words;

    while (pointer != NULL) { //putting the credentials into vector
        words.push_back(pointer);
        pointer = strtok(NULL," "); 
    }

    username = (char*)words.at(1).c_str();

    cout<<"USERNAME:"<<endl;
    cout<<username<<endl;


    ifstream myfile;
    myfile.open ("./AddOn/users.txt");
    if (!myfile.is_open()) {
      ret.msg = "ERROR: File open";
      ret.success = false;
      return ret;
    }
    bool found = false;
    string user, password;
    while (myfile >> user >> password){
        if(user.compare(username) == 0) found = true;
    }   
    myfile.close();

    if(found){

        //TODO RICAVARE LA CHIAVE PUBBLICA DI TALE CLIENT 
        setClientPublicKey(client,username);
        
        string response = "Client successfully recognize!";
        int numBytesSent = send(client.getFileDescriptor(), response.c_str(), strlen(response.c_str()), 0);
        if (numBytesSent < 0) { // send failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
        }
        if ((uint)numBytesSent < response.size()) { // not all bytes were sent
        ret.success = false;
        char err_msg[100];
        sprintf(err_msg, "Only %d bytes out of %lu was sent to client", numBytesSent, response.size());
        ret.msg = err_msg;
        return ret;
        }

        ret.msg = "Client recognized";
        ret.success = true;
        return ret;
    } else{
        ret.success = false;
        ret.msg = "Client not recognize";
        return ret;
    }

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

        Client& receivingClient = sendRequest(client,request);
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
    else if (strncmp(request.c_str(),":REG",4) == 0) {
        if (!client.isAuthenticated()) {
            // Cannot start normal flow until authentication is estabilished
        }
        string response = regClient(client,request);
        ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
    }
    else if (strncmp(request.c_str(),":ACCEPT",7) ==0 ) {
        // Recover the requesting client from the receiver client istance, and forward the ACCEPT message
        Client &requestingClient = getClient(client);
        if (requestingClient == client) {
            // The requesting client probably disconnected
            string response = "The requesting client is disconnected";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        }
        else {
            
            unsigned char *messageOne = recoverKey(requestingClient,client);
            unsigned char *messageTwo = recoverKey(client,requestingClient);
            storeRequestingInfo(requestingClient,client);

            ret = sendToClient(requestingClient,(char*)messageOne,strlen((char*)messageOne));
            ret = sendToClient(client,(char*)messageTwo,strlen((char*)messageTwo));
        }
    }
    else if (strncmp(request.c_str(),":CERT",5) == 0 ) {
        ret = sendCertificate(client);
    }
    else if (strncmp(request.c_str(),":USER",5) == 0 ) {
        ret = checkClientIdentity(client,request);
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
void TcpServer::publishClientMsg(Client & client, const char * msg, size_t msgSize) {
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
void TcpServer::publishClientDisconnected(Client & client) {
    for (uint i=0; i<m_subscribers.size(); i++) {
        if (m_subscribers[i].wantedIp == client.getIp()) {
            if (m_subscribers[i].disconnected_func != NULL) {
                (*m_subscribers[i].disconnected_func)(client);
            }
        }
    }
}

/**
 * 
 */ 
void TcpServer::loadServerDHKeys() {

    string path1 = "./AddOn/serverDHkey.pem"; 
    FILE *file1 = fopen(path1.c_str(),"r");
    if (!file1) handleErrors();

    EVP_PKEY *privkey = PEM_read_PrivateKey(file1,NULL,NULL,NULL);
    if (!privkey) handleErrors(); 

    fclose(file1);

    string path2 = "./AddOn/serverDHpubkey.pem"; 
    FILE *file2 = fopen(path2.c_str(),"r");
    if (!file2) handleErrors();

    EVP_PKEY *pubkey = PEM_read_PUBKEY(file2,NULL,NULL,NULL);
    if (!pubkey) handleErrors(); 

    setServerDHkeypair(privkey,pubkey);

    fclose(file2);

} 


/*
 * Bind port and start listening
 * Return tcp_ret_t
 */
pipe_ret_t TcpServer::start(int port) {

    // Load server private key
    string path = "./AddOn/ChatBox/ChatBox_App_key.pem"; 
    FILE *file = fopen(path.c_str(),"r");
    if (!file) handleErrors();

    EVP_PKEY *privkey = PEM_read_PrivateKey(file,NULL,NULL,NULL);
    if (!privkey) handleErrors(); 
    setServerPrivKey(privkey);

    fclose(file);

    // Load server DH keypair
    loadServerDHKeys();

    cout << "Server saved key successfully" << endl;

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
        //cout << "Entra nel loop?" << endl;
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


pipe_ret_t TcpServer::sendCertificate(Client & client){

    pipe_ret_t ret;

    // READ CERTIFICATE 

    X509* server_cert;
    FILE* server_file = fopen("./AddOn/ChatBox/ChatBox_App_cert.pem","r");
    if(!server_file) { 
        ret.success = false;
        ret.msg = "Error opening certificate file";
        return ret;
    }
    server_cert = PEM_read_X509(server_file,NULL,NULL,NULL);
    if(!server_cert) {
        ret.success = false;
        ret.msg = "Error reading the certificate";
        return ret;
    }

    fclose(server_file);

    size_t cert_len;
    unsigned char* certificate = pem_serialize_certificate(server_cert,&cert_len);
    cout<<"CERTIFICATE:"<<endl;
    cout<<certificate<<endl;
    int numBytesSent = send(client.getFileDescriptor(), certificate, cert_len, 0);
    if (numBytesSent < 0) { // send failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }
    if ((uint)numBytesSent < cert_len) { // not all bytes were sent
        ret.success = false;
        char msg[100];
        sprintf(msg, "Only %d bytes out of %lu was sent to client", numBytesSent, cert_len);
        ret.msg = msg;
        return ret;
    }
    ret.success = true;
    // return ret;

    // Now server will send its public key generated with diffie hellman parameters
    size_t key_len;
    unsigned char* publicKey = pem_serialize_pubkey(getDHPublicKey(),&key_len);
    cout<<"DH PUBKEY:"<<endl;
    cout<<publicKey<<endl;
    int numBytesSent2 = send(client.getFileDescriptor(), publicKey, key_len, 0);
    if (numBytesSent2 < 0) { // send failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }
    if ((uint)numBytesSent2 < key_len) { // not all bytes were sent
        ret.success = false;
        char msg[100];
        sprintf(msg, "Only %d bytes out of %lu was sent to client", numBytesSent2, key_len);
        ret.msg = msg;
        return ret;
    }
    ret.success = true;

    // Now server will wait for client authentication via its RSA public key obtained with the certificate
    // Client encrypt the hash of the diffie hellman with the RSA pubkey of the server. The server decrypt it
    // using its private RSA key and verify if the hash correspond
    
    return ret;

}

/*
 * Send message to specific client (determined by client IP address).
 * Return true if message was sent successfully
 */
pipe_ret_t TcpServer::sendToClient(Client & client, const char * msg, size_t size){
    pipe_ret_t ret;

    if (client.isChatting()) {
        int numBytesSent = send(client.getFileDescriptor(),msg,size,0);
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

    else {

        if (strncmp(msg,":KEY",4)==0) {
            client.setChatting();
        }

        // Derive the shared secret
        EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(serverDHPrivKey, NULL);
        EVP_PKEY_derive_init(ctx_drv);
        if (1 != EVP_PKEY_derive_set_peer(ctx_drv, client.getClientKey())) {
            handleErrors();
        }
        unsigned char* secret;

        /* Retrieving shared secret’s length */
        size_t secretlen;
        if (1 != EVP_PKEY_derive(ctx_drv, NULL, &secretlen)) {
            handleErrors();
        }
        /* Deriving shared secret */
        secret = (unsigned char*)malloc(secretlen);
        if (secret == NULL) {
            handleErrors();
        }
        if (1 != EVP_PKEY_derive(ctx_drv, secret, &secretlen)) {
            handleErrors();
        }
        EVP_PKEY_CTX_free(ctx_drv);

        // We need to derive the hash of the shared secret now
        unsigned char* digest;
        unsigned int digestlen;
        EVP_MD_CTX* digest_ctx;
        /* Buffer allocation for the digest */
        digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
        /* Context allocation */
        digest_ctx = EVP_MD_CTX_new();

        /* Hashing (initialization + single update + finalization */
        EVP_DigestInit(digest_ctx, EVP_sha256());
        EVP_DigestUpdate(digest_ctx, secret, sizeof(secret));
        EVP_DigestFinal(digest_ctx, digest, &digestlen);
        /* Context deallocation */
        EVP_MD_CTX_free(digest_ctx);

        // Taking first 128 bits of the digest
        // Get first 16 bytes of shared secret, to use as key in AES
        unsigned char *key = (unsigned char*)malloc(16);
        // for (int i =0; i<16; i++) {
        //     key[i] = digest[i];
        // }
        memcpy(key,digest,16);

        // Also this first part could be included in a utility function
        unsigned char msg2[size];
        strcpy((char*)msg2,msg);

        // unsigned char key_gcm[] = "1234567890123456";
        unsigned char iv_gcm[] = "123456780912";
        unsigned char *cphr_buf;
        unsigned char *tag_buf;
        int cphr_len;
        int tag_len;
        int pt_len = strlen(msg);

        cphr_buf = (unsigned char*)malloc(size);
        tag_buf = (unsigned char*)malloc(16);
        cphr_len = gcm_encrypt(msg2,pt_len,iv_gcm,12,key,iv_gcm,12,cphr_buf,tag_buf);

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


/**
 * This function will be called each time the server need to create a DH key pair 
 * in order to connect with another client (maybe not since a unique public key can be used)
 */
EVP_PKEY* generatePubkey() {

    EVP_PKEY* dh_params;
    DH* tmp = get_dh2048();
    dh_params = EVP_PKEY_new();
    // Loading the dh parameters into dhparams structure
    int res = EVP_PKEY_set1_DH(dh_params,tmp);
    DH_free(tmp);

    if (res == 0) {
        std::cout << "There was a problem in (p,g) DH parameters generation\nAborting...";
        return 0;
    }

    // Creating public key for the user
    std::string pubkey_filename;

    cout << "Generating public key, please insert file name: ";
    getline(cin,pubkey_filename);

    // Generation of the public key
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY* my_pubkey = NULL;
    EVP_PKEY_keygen_init(ctx);
    if (EVP_PKEY_keygen(ctx, &my_pubkey)!=1) {
        cout << "There was a problem in (p,g) DH parameters generation\nAborting...";
        return 0;
    }

    FILE *fp_my_pubkey = fopen(pubkey_filename.c_str(),"wx");

    // Saving pubkey to file
    if (PEM_write_PUBKEY(fp_my_pubkey,my_pubkey) != 1) {
        cout << "There was a problem in (p,g) DH parameters generation\nAborting...";
        return 0;
    }
    fclose(fp_my_pubkey);



}