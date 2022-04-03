#include <string>

class User {
    public:
        User(std::string username_, std::string password_, bool admin_, int size_) : 
            username(username_), password(password_), admin(admin_), size(size_) {}
        std::string get_username();
        std::string get_password();
        bool is_admin();
        int get_size();
        void decreaseSize(int size_);
    private:
        std::string username;
        std::string password;
        bool admin;
        int size;
};
