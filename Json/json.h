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
    void break_data(int i);
    void find_user_data();
    void parse_files();
    void parse_users();
    void parse(std::string json_data);
    std::string remove_whitespace(std::string str);
    std::vector<User> get_users();
    std::vector<std::string> get_files();
    std::string getCommandPort();
    std::string getDataPort();
};
