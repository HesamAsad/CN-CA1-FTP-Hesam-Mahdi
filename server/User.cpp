#include "User.h"

void User::decreaseSize(int size_) {
    size -= size_;
}

std::string User::get_username() { return username; }

std::string User::get_password() { return password; }

bool User::is_admin() { return admin; }

int User::get_size() { return size; }