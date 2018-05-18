#include "user.hpp"

User::User(int id, const QString &name, const QString &password, Type type):
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

User::Type User::type() const
{
    return mType;
}

void User::setType(const Type &type)
{
    mType = type;
}
