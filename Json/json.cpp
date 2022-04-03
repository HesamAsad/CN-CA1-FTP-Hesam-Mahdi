#include "json.h"

std::vector<std::string> data;
std::vector<std::string> admin_files;
std::string commandPort;
std::string dataPort;
std::vector<User> user_list;
std::string users_str;
std::string files_str;


void Json::breakData(int i){
    int j = 0;
    int size = 0;
    std::string username;
    std::string password;
    bool admin;
    std::string str;
    while(j < data[i].length()) {
        if(str == "user") {
            j += 1;
            str = "";
            while(data[i][j] != ',' && j < data[i].length()){
                str += data[i][j];
                j++;
            }
            username = str;
            str = "";
            j++;
            continue;
        }
        else if(str == "password") {
            j += 1;
            str = "";
            while(data[i][j] != ',' && j < data[i].length()){
                str += data[i][j];
                j++;
            }
            password = str;
            str = "";
            j++;
            continue;
        }
        else if(str == "admin"){
            j += 1;
            str = "";
            while(data[i][j] != ',' && j < data[i].length()){
                str += data[i][j];
                j++;
            }
            if(str == "true")
                admin = true;
            else
                admin = false;
            str = "";
            j++;
            continue;
        }
        else if(str == "size"){
            j += 1;
            str = "";
            while(data[i][j] != ',' && j < data[i].length()){
                size = size * 10;
                size = size + (data[i][j] - '0');
                j++;
            }
            str = "";
            j++;
            continue;
        }
        str += data[i][j];
        j++;
    }
    User u = User(username, password, admin, size);
    user_list.push_back(u);
}

void Json::findUserData() {
    for(int i = 0; i < data.size(); i++)
        breakData(i);
}

void Json::parseFiles() {
    int i =0;
    std::string file;
    while(i < files_str.length()) {
        if(files_str[i] == ',') {
            admin_files.push_back(file);
            i++;
            file = "";
            continue;
        }
        file += files_str[i];
        i++;
    }
    if(file != "")
        admin_files.push_back(file);
}

void Json::parseUsers() {
    std::string str;
    int i = 0;
    while(i < users_str.length()) {
        if(users_str[i] == '{' ) {
            i++;
            continue;
        }
        if(users_str[i] == '}') {
            if(str[str.length() - 1] == ',')
                str.erase(str.end() - 1);
            data.push_back(str);
            str = "";
            i += 3;
        }
        str += users_str[i];
        i++;
    }
}

void Json::parse(std::string json_data) {
    std::string str;
    int i = 0;
    while(i < json_data.length()) {
        if (json_data[i] == ',') {
            i += 1;
            continue;
        }
        if(str == "users") {
            i +=2;
            str = "";
            while(json_data[i] != ']') {
                str += json_data[i];
                i++;
            }
            users_str = str;
            str = "";
            i++;
            continue;
        }
        else if(str == "files") {
            i +=2;
            str = "";
            while(json_data[i] != ']') {
                str += json_data[i];
                i++;
            }
            files_str = str;
            str = "";
            i++;
            continue;
        }
        else if(str == "dataChannelPort") { 
            i += 1;
            str = "";
            while(json_data[i] != ','){
                str += json_data[i];
                i++;
            }
            dataPort = str;
            str = "";
            i++;
            continue;
        }
        else if(str == "commandChannelPort") {
            i += 1;
            str = "";
            while(json_data[i] != ','){
                str += json_data[i];
                i++;
            }
            commandPort = str;
            str = "";
            i++;
            continue;
        }
        str += json_data[i];
        i++;
    }
}

std::string Json::removeWhitespace(std::string str){
    std::string json_data;
    for(int i = 0; i < str.length(); i++){
        if(isspace(str[i]) || str[i] == '\n' || str[i] == '\t')
            continue;
        json_data += str[i];
    }
    return json_data;
}

void Json::jsonParser(){
    std::ifstream fin;
    fin.open("../server/config.json");
    std::string str, json_data;
    while(getline(fin, str))
        json_data += str;
    json_data = removeWhitespace(json_data);
    json_data.erase(json_data.begin());
    json_data.erase(json_data.end()-1);
    json_data.erase(std::remove(json_data.begin(), json_data.end(), '\"'), json_data.end());
    parse(json_data);
    parseUsers();
    parseFiles();
    findUserData();
}

std::vector<User> Json::getUsers() { return user_list; }
std::vector<std::string> Json::getFiles() { return admin_files; }
std::string Json::getCommandPort() { return commandPort; }
std::string Json::getDataPort() { return dataPort; }
