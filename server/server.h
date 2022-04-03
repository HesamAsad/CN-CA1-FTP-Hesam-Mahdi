#include "tools.h"

#define REQUEST_ADDR "127.0.0.1"
#define DATA_ADDR "127.0.0.2"
#define CLIENT_COUNT 50

class  Server {
  public:
    Server() {
      json = Json();
      parse_json();
    }
    void parse_json();
    socketData handleConnections();
    void connectCh(char* argv[]);
    bool findUsername(std::string);
    bool findPass(std::string , std::string, bool*);
    void handleUser(std::string*, bool*, bool, int, int, std::vector<std::string>);
    void handlePass(std::string, bool*, bool*, int, int, std::vector<std::string>, bool*);
    void handleInfo(void* );
    void handleHelp(std::vector<std::string>, int, int, bool, bool, std::string);
    void send_help(int);
    void handle_ls(std::vector<std::string>, int, int, bool, bool, std::string, std::string);
    void handle_cwd(std::vector<std::string>, int, int, bool, bool, std::string*, std::string);
    void handle_pwd(std::vector<std::string>, std::string, int, int, bool, bool, std::string, std::string);
    void handle_mkd(std::vector<std::string>, int, int, bool, bool, std::string, std::string);
    void handle_dele(std::vector<std::string>, int, int, bool, bool, std::string, bool, std::string);
    void handle_dl(std::vector<std::string>, int, int, bool, bool, bool, std::string, std::string);
    std::vector<std::string> parse_command(char[]);
    void handle_quit(std::vector<std::string>, int, int, bool*, bool*, std::string*,bool*, std::string*);
    void printTime();
    void handle_rename(std::vector<std::string>, int, int, bool, bool, bool, std::string, std::string);
    void handle_error(int, int);
    std::string checkForServer(std::string cwd, bool*);

  private:
    Json json;
    std::ofstream logs;
    int clientSockets[CLIENT_COUNT] = {0};
    int dataSockets[CLIENT_COUNT] = {0};
    struct sockaddr_in request_serverAddr;
    struct sockaddr_in data_serverAddr;
    int request_channel;
    int data_channel;
    std::vector<User> users_list;
    std::vector<std::string> protected_files;
    std::vector<std::string> login_commands{"pwd", "mkd", "dele", "ls", "cwd", "rename", "retr", "help", "quit"};
    std::vector<std::string> help;

    void printLoginError(std::string, int, int);
    void printSyntaxError(std::string, int, int, std::string);
};
