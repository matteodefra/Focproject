#include "../include/tcp_server.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <fstream>
#include <assert.h>
#include "../include/util.h"

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
        string connected = m_clients[i].isConnected() ? "True" : "False";
        cout << "-----------------\n" <<
                  "IP address: " << m_clients[i].getIp() << std::endl <<
                  "Connected?: " << connected << std::endl <<
                  "Socket FD: " << m_clients[i].getFileDescriptor() << std::endl;
        cout<<"-----------------"<<endl;
    }
}


/**
 * Server will receive authentication from the client and will check its public key 
 * (which is stored from start as guideline). Than will communicate its certificate 
 * authority in order to prove its affidability. Then symmetric key is negotiated
 */
pipe_ret_t TcpServer::authenticationStart(Client& client, string msg) {

    pipe_ret_t ret;

    ret = checkClientIdentity(client,msg);

    if(ret.success == false) return ret;

    //:CERT request message

    unsigned char cert_req_msg[MAX_PACKET_SIZE];
    int numOfBytesReceived = recv(client.getFileDescriptor(), cert_req_msg, MAX_PACKET_SIZE, 0);;

    if(numOfBytesReceived < 1) {
        ret.msg = "Error receinving the certificate request";
        ret.success = false;
        return ret;
    }

    if(strncmp((char*)cert_req_msg,":CERT",5) != 0) {
        ret.msg = "Certificate request message not as expected";
        ret.success = false;
        return ret;
    }

    cout<<"Certificate Request received."<<endl;

    ret = sendCertificate(client);
    if(ret.success == false) return ret;

    ret = verifySignature(client);
    if(ret.success == false) return ret;

    ret = sendDHPubkey(client);
    if(ret.success == false) return ret;

    ret = receiveClientPubkeyDH(client);
    if(ret.success == false) return ret;

    // send certificate
    // negotiate elliptic curve diffie hellman key
    cout<<"Authentication completed, DH keys exchanged successfully."<<endl;
    cout<<endl;
    ret.msg = "Authentication completed, DH keys exchanged";
    ret.success = true;
    return ret;
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
        memset(msg,0,MAX_PACKET_SIZE);
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
            cout<<"-----------------"<<endl;
            cout<<"Message received from client"<<endl;

            if (client->isChatting()) {
                // Client send the message to the other party
                // Get the client socket from the client istance and forward it
                cout<<"Forwarding message to the other client . . ."<<endl;
                Client &receiver = getClient(*client);

                sendToClient(receiver,msg,numOfBytesReceived);
            }
        
            else {
                if(strncmp(msg,":USER",5) == 0){ //These msg are sent in clear during the authentication phase
                    processRequest(*client,msg);
                } 
                else{

                    unsigned char* plaintext_buffer = deriveAndDecryptMessage(msg,numOfBytesReceived, getDHPublicKey(), client->getClientKeyDH());

                    cout << "<" << client->getClientName() <<"> " << plaintext_buffer << endl;

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
        if (strcmp(s.getClientName().c_str(),pointer)==0 && s.isLogged()) {
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
 * return 0 if the pair is present
 * return 1 if an error occurs during the login
 * return 2 if the pair is not present
 */
int checkLogin(string username, string psw){

    ifstream myfile;
    myfile.open ("./AddOn/users.txt");
    if (!myfile.is_open()) {
      cout<<"ERROR: File open"<<endl;
      return 1;
    }
    string user, password;
    while (myfile >> user >> password){
        if(user.compare(username) == 0 && password.compare(psw) == 0) return 0; 
    }   
    myfile.close();

    return 2;
}


/**
 * Login function: memorize client name and send back an OK ack in order to manage list of connected clients
 */
string TcpServer::loginClient(Client &client, string message) {

    char *pointer = strtok((char*)message.c_str()," ");
    vector<string> credentials; //at.() = username | at.(1) = password

    credentials.push_back(client.getClientName());
    int counter = 0;

    while (pointer != NULL) { //putting the credentials into vector
        if(counter != 0) credentials.push_back(pointer);
        pointer = strtok(NULL," "); 
        counter++;
    }    

    int ret_code = checkLogin(credentials.at(0),credentials.at(1));
    string response;
    
    switch(ret_code){
        case 0: 
            response = "Login successful, welcome to the chatting platform!";
            client.setLogged();
            break;
        case 1: 
            response = "An error occurred during the login phase, please try again later";
            break;
        case 2: 
            response = "We cant find an user with that credentials, try a different username or password";
            break;
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
        if(s.isLogged()) {
            string clientName = s.getClientName();
            allClients = allClients + " " + clientName + ",";
        }
    }
    if (allClients == "[") {
        allClients = allClients + "]";        
    }
    else {
        allClients.pop_back();
        allClients = allClients + " ]";   
    }
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

    size_t keylen;
	unsigned char *key = pem_serialize_pubkey(clientTwo.getClientKeyDH(), &keylen);

    if (!key) {
        handleErrors();
    }

    int pos = 0;
    auto *buffer = new unsigned char[5+keylen];

    memcpy(buffer+pos,":KEY ",5);
    pos += 5;

    memcpy(buffer+pos,key,keylen);

    free(key);

    return buffer;
}


void setClientPublicKey(Client &client, char *username) {

    string name(username);

    string path = "./AddOn/" + name + "_pubRSA.pem";    


    FILE *file = fopen(path.c_str(),"r");
    if (!file) {
        handleErrors();
    }

    EVP_PKEY *pubkey = PEM_read_PUBKEY(file,NULL,NULL,NULL);
    if (!pubkey) {
        handleErrors();
    }
    cout << "Retrieving the RSA client public key, already known" << endl;
    cout << "Pubkey retrieved: " << pubkey << endl;

    client.setClientKeyRSA(pubkey);

    fclose(file);

    cout << "Set also client public key successfully" << endl;
}


/**
 * 
 */

pipe_ret_t TcpServer::checkClientIdentity(Client& client, string msg){
    
    cout<<"Message received: "<<msg<<endl;
    cout<<"-----------------"<<endl;
    cout<<"Looking for the user in the database . . ."<<endl;

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


        cout<<"User successfully found."<<endl;
        //TODO RICAVARE LA CHIAVE PUBBLICA DI TALE CLIENT 
        setClientPublicKey(client,username);
        client.setClientName(username);
        if(strcmp(username,"admin") == 0) client.setAdmin();
        
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

    cout<<"-----------------"<<endl;
    cout<<"Sending the response . . ."<<endl;
    
    pipe_ret_t ret;

    if (strncmp(request.c_str(),":LIST",5) == 0) {
        if (!client.isLogged()) {
            string response = "You must be logged before issuing this command";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        } else{
            string clientsList = createList(client,request);
            ret = sendToClient(client,clientsList.c_str(),strlen(clientsList.c_str()));
        }
    }
    else if (strncmp(request.c_str(),":REQ",4) == 0) {
        if (!client.isLogged()) {
            // Cannot start a request-to-talk until a login is provided
            string response = "You must be logged before issuing this command";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        } else{
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
                receivingClient.setRequest();
            }
        }
       
    }
    else if (strncmp(request.c_str(),":LOGIN",6) == 0) {
        if (client.isLogged()) {
            // Cannot start a request-to-talk until a login is provided
            string response = "You are already logged!";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        }
        // A must function: each client must furnish a login name
        string response = loginClient(client,request);
        ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
    }
    else if (strncmp(request.c_str(),":REG",4) == 0) {

         if (!client.isLogged()) {
            // Cannot start a request-to-talk until a login is provided
            string response = "You must be logged before issuing this command";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        } else if(!client.isAdmin()){
            //this command can be performed only if the client is an admin
            string response = "This action can be performed only by an administrator";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        } else{ 
            string response = regClient(client,request);
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        }

    }
    else if (strncmp(request.c_str(),":DENY",5) == 0) {
        if (!client.isLogged()) {
            // Cannot start a request-to-talk until a login is provided
            string response = "You must be logged before issuing this command";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        } 
        else if (!client.hasRequest()){
            string response = "You dont have any pending request.";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        } else {
            Client &requestingClient = getClient(client);
            if (requestingClient == client) {
                // The requesting client probably disconnected
                string response = "The requesting client is disconnected";
                ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
            } else{
                client.resetRequest();
                string response = "Request denied";
                ret = sendToClient(requestingClient,(char*)response.c_str(),strlen(response.c_str()));
            }
        }
    }
    else if (strncmp(request.c_str(),":ACCEPT",7) ==0 ) {
        if (!client.isLogged()) {
            // Cannot start a request-to-talk until a login is provided
            string response = "You must be logged before issuing this command";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        } 
        else if (!client.hasRequest()){
            string response = "You dont have any pending request.";
            ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
        } else {
            Client &requestingClient = getClient(client);
            if (requestingClient == client) {
                // The requesting client probably disconnected
                string response = "The requesting client is disconnected";
                ret = sendToClient(client,response.c_str(),strlen(response.c_str()));
            }
            else {

                cout<<"Exchanging the keys between the two clients . . ."<<endl;
                
                unsigned char *messageOne = recoverKey(requestingClient,client);
                unsigned char *messageTwo = recoverKey(client,requestingClient);
                storeRequestingInfo(requestingClient,client);

                cout << "First message to send: " <<endl;
                cout<<messageOne;
                cout<<"-----------------"<<endl;
                cout << "Second message to send" << endl;
                cout << messageTwo;
                cout<<"-----------------"<<endl;

                ret = sendToClient(requestingClient,(char*)messageOne,strlen((char*)messageOne));
                ret = sendToClient(client,(char*)messageTwo,strlen((char*)messageTwo));
                client.resetRequest();
            }
        }
    }
    else if (strncmp(request.c_str(),":USER",5) == 0 ) {
        ret = authenticationStart(client,request);
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
            EVP_PKEY_free(m_clients[i].getClientKeyRSA());
            EVP_PKEY_free(m_clients[i].getClientKeyDH());
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

    EVP_PKEY* dh_params;
    DH* tmp = get_dh2048();
    dh_params = EVP_PKEY_new();
    // Loading the dh parameters into dhparams structure
    int res = EVP_PKEY_set1_DH(dh_params,tmp);
    DH_free(tmp);

    if (res == 0) {
        cout << "There was a problem in (p,g) DH parameters generation\nAborting...";
        return;
    }

    // Generation of the public key
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY* my_pubkey = NULL;
    EVP_PKEY_keygen_init(ctx);
    if (EVP_PKEY_keygen(ctx, &my_pubkey)!=1) {
        cout << "There was a problem in (p,g) DH parameters generation\nAborting...";
        return;
    }

    EVP_PKEY_CTX_free(ctx);

    setServerDHPubKey(my_pubkey);

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

    // !!!!!
    EVP_PKEY_free(privkey);

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

pipe_ret_t TcpServer::receiveClientPubkeyDH(Client & client){

    pipe_ret_t ret;

    unsigned char pubkey_dh[MAX_PACKET_SIZE];
    int numOfBytesReceived = recv(client.getFileDescriptor(), pubkey_dh, MAX_PACKET_SIZE, 0);;

    cout<<"Receiving client DH pubkey . . ."<<endl;

    if(numOfBytesReceived < 1) {
        ret.msg = "Error receinving the certificate request";
        ret.success = false;
        return ret;
    }

    cout << "Client DH pubkey: " << endl;
    cout<< pubkey_dh; 
    cout<<"-----------------"<<endl;

    EVP_PKEY* pubkeyDH = pem_deserialize_pubkey(pubkey_dh,numOfBytesReceived);
    client.setClientKeyDH(pubkeyDH);
    ret.success = true;
    return ret;

}


pipe_ret_t TcpServer::verifySignature(Client & client){

    pipe_ret_t ret;

    // Now server will receive signature of a message encrypted with client private key. Server will verify 
    // the authencity through its known public key
    char signature[MAX_PACKET_SIZE];
    memset(signature,0,MAX_PACKET_SIZE);
    int numOfBytesReceived = recv(client.getFileDescriptor(), signature, MAX_PACKET_SIZE, 0);

    cout << "Signature received." << endl;

    if(numOfBytesReceived < 1) {
        client.setDisconnected();
        if (numOfBytesReceived == 0) { //client closed connection
            client.setErrorMessage("Client closed connection");
        } else {
            client.setErrorMessage(strerror(errno));
        }
        close(client.getFileDescriptor());
        publishClientDisconnected(client);
        deleteClient(client);
        ret.success = false;
        return ret;
    }
    else {

        char *clear_buf = (char*)client.getClientName().c_str();
        strcat(clear_buf," user");
        int clear_size = strlen(clear_buf);

        int res;
        // Verify the signature in the file
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            cout << "ERROR1!" << endl;
            ERR_print_errors_fp(stderr);
            ret.success = false;
            return ret;
        }

        res = EVP_VerifyInit(md_ctx,EVP_sha256());
        if (res == 0) {
            cout << "ERROR2!" << endl;
            ERR_print_errors_fp(stderr);
            ret.success = false;
            return ret;
        }

        res = EVP_VerifyUpdate(md_ctx,clear_buf,clear_size);
        if (res == 0) {
            cout << "ERROR3!" << endl;
            ERR_print_errors_fp(stderr);
            ret.success = false;
            return ret;
        }

        res = EVP_VerifyFinal(md_ctx,(unsigned char*)signature,numOfBytesReceived,client.getClientKeyRSA());
        if (res == 0) {
            cout << "ERROR4!" << endl;
            ERR_print_errors_fp(stderr);
            ret.success = false;
            return ret;
        }

        cout << "Signature verified correctly! Client is authorized." << endl;
        ret.success = true;
        return ret;
    }


}

pipe_ret_t TcpServer::sendDHPubkey(Client & client){

    pipe_ret_t ret;

    cout<<"Sending Server DH public key to client . . ."<<endl;

    
    // Now server will send its public key generated with diffie hellman parameters
    size_t key_len;
    unsigned char* publicKey = pem_serialize_pubkey(getDHPublicKey(),&key_len);
    cout<<"Server DH pubkey:"<<endl;
    cout<<publicKey;
    cout<<"-----------------"<<endl;
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
    free(publicKey);
    
    return ret;

}

pipe_ret_t TcpServer::sendCertificate(Client & client){

    cout<<"Sending the certificate . . ."<<endl;

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


    // Double send!!!
    size_t cert_len;
    unsigned char* certificate = pem_serialize_certificate(server_cert,&cert_len);
    cout<<"Server certificate:"<<endl;
    cout<<certificate;
    cout<<"-----------------"<<endl;
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
    

    OPENSSL_free(certificate);
    
    return ret;

    /* */
 

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
            cout << "Setting client in chatting mode" << endl;
            client.setChatting();
        }

        auto* buffer = deriveAndEncryptMessage(msg,size,getDHPublicKey(),client.getClientKeyDH());

        cout << "Server, dumping the encrypted payload: " << endl;
        BIO_dump_fp(stdout,(char*)buffer,strlen((char*)buffer));
        cout<<"-----------------"<<endl;
        cout<<endl;

        int numBytesSent = send(client.getFileDescriptor(), buffer, 12/*aad_len*/+strlen(msg)+16/*tag_len*/+IV_LEN/*iv_len*/, 0);
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

/*
 * Close server and clients resources.
 * Return true is success, false otherwise
 */
pipe_ret_t TcpServer::finish() {
    pipe_ret_t ret;
    for (uint i=0; i<m_clients.size(); i++) {
        m_clients[i].setDisconnected();
        EVP_PKEY_free(m_clients[i].getClientKeyDH());
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
    EVP_PKEY_free(getServerPrivKey());
    EVP_PKEY_free(getDHPublicKey());
    ret.success = true;
    return ret;
}