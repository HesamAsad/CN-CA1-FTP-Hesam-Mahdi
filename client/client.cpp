#include "client.h"

struct sockaddr_in addrSocket;
struct sockaddr_in dataSocketAddr;
int broadcastFD;
int dataFD;


void Client::connectCh(char* ports[]) {
    if((broadcastFD = socket(AF_INET, SOCK_STREAM, 0)) < 0 ||
        (dataFD = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cout << "failed to open socket" << std::endl;
        exit(EXIT_FAILURE);
    }
    addrSocket.sin_family = AF_INET;
    addrSocket.sin_port = htons(atoi(ports[0]));
    addrSocket.sin_addr.s_addr = inet_addr(REQUEST_ADDR);
    dataSocketAddr.sin_family = AF_INET;
    dataSocketAddr.sin_port = htons(atoi(ports[1]));
    dataSocketAddr.sin_addr.s_addr = inet_addr(DATA_ADDR);
    if(connect(broadcastFD, (struct sockaddr*) &addrSocket, sizeof(addrSocket)) < 0
        || connect(dataFD, (struct sockaddr*) &dataSocketAddr, sizeof(dataSocketAddr)) < 0){
      std::cout << "failed to connect" << std::endl;
      exit(EXIT_FAILURE);
    }
    int port;
    char* in = new char[250];
    recv(broadcastFD, in, 250, 0);
    std::cout << in << std::endl;
    delete in;
    in = new char[250];
    recv(dataFD, in, 250, 0);
    std::cout << in << std::endl;
    delete in;
}

void Client::handleInfo() {
    char in[256];
    std::cin.getline(in, 256);
    if(send(broadcastFD, in, sizeof(in), 0) < 0)
        exit(EXIT_FAILURE);
    if(strcmp(in, "exit") == 0)
        exit(EXIT_SUCCESS);
    if(strcmp(in, "help") == 0){
        handleHelp();
        return;
    }
    else if(in[0] == 'l' && in[1] == 's') {     //ls
        handle_ls();
        return;
    }
    else if (in[0] == 'r' && in[1] == 'e' && 
                in[2] == 't' && in[3] == 'r') {        //retr
        handle_dl(in+5);
        return;
    }
    char* msg = new char[256]; 
    recv(broadcastFD, msg, 256, 0);
    std::cout << msg << std::endl;
}

void Client::handleHelp() {
    char* msg = new char[256]; 
    recv(broadcastFD, msg, 256, 0);
    msg[strlen(msg)] = '\0';
    std::cout << msg << std::endl;
    if(strcmp(msg, "214") != 0) {
        delete msg;
        return;
    }
    delete msg;
    char in[1200];
    recv(broadcastFD, in, 1200, 0);
    std::cout<<in<<std::endl;
}

void Client::handle_dl(char* file_name) {
    char* result = new char[256];
    memset(result, 0, 256);
    recv(broadcastFD, result, 256, 0);
    if(result[0] == '!') {
        std::cout << result+1 << std::endl;
        return;
    }

    char* msg = new char[50];
    std::string file_content = "";
    memset(msg, 0, 50);
    recv(dataFD, msg, 50, 0);
    file_content += msg;
    memset(msg, 0, 50);
    while(1) {
        int r = recv(dataFD, msg, 50, MSG_DONTWAIT);
        if(r <= 0)
            break;
        file_content += msg;
        memset(msg, 0, 50); 
    }
    std::ofstream out(file_name);
    out << file_content;
    out.close();
    std::cout << result+1 << std::endl;
    delete result;
    delete msg;
}

void Client::handle_ls() {
    char* result = new char[2];
    memset(result, 0, 2);
    recv(broadcastFD, result, 2, 0);
    result[strlen(result)] = '\0';
    if(strcmp(result, "!") == 0){
        delete result;
        char* msg = new char[256];
        memset(msg, 0, 256);
        recv(broadcastFD, msg, 256, 0);
        std::cout<<msg<<std::endl;
        return;
    }

    char* msg = new char[256];
    memset(msg, 0, 256);
    recv(dataFD, msg, 256, 0);
    std::cout << msg;
    memset(msg, 0, 256);
    for(int i = 0; !(recv(dataFD, msg, 256, MSG_DONTWAIT) < 0); i++) {
        std::cout << msg;
        memset(msg, 0, 256); 
    }
    recv(broadcastFD, msg, 256, 0);
    std::cout << msg << std::endl; 
}

char* str2charstar(std::string s) {
  char* p = new char[s.length() + 1];
  int i;
  for (i = 0; i < s.length(); i++)
      p[i] = s[i];
  p[s.length()] = '\0';
  return p;
}
