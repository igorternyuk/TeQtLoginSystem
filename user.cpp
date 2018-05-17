#include "user.hpp"

User::User(int id, const QString &name, const QString &password):
    mId(id), mName(name), mPassword(password)
{}

int User::id() const
{
    return mId;
}

void User::setId(int id)
{
    mId = id;
}

QString User::name() const
{
    return mName;
}

void User::setName(const QString &name)
{
    mName = name;
}

QString User::password() const
{
    return mPassword;
}

void User::setPassword(const QString &password)
{
    mPassword = password;
}
