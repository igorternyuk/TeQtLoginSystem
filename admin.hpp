#ifndef ADMIN_H
#define ADMIN_H

#include "user.hpp"

class Admin: public User
{
public:
    explicit Admin(int id = -1, const QString &name = "",
                   const QString &password = "");
};

#endif // ADMIN_H
