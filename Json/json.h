#include <iostream>
#include <fstream>
#include <string>
#include <ctype.h>
#include <algorithm>
#include <vector>
#include "../server/User.h"


class Json {
  public:
    void jsonParser();
    void breakData(int i);
    void findUserData();
    void parseFiles();
    void parseUsers();
    void parse(std::string json_data);
    std::string removeWhitespace(std::string str);
    std::vector<User> getUsers();
    std::vector<std::string> getFiles();
    std::string getCommandPort();
    std::string getDataPort();
};
