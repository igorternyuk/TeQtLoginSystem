#ifndef USER_H
#define USER_H

#include <QString>

class User
{
public:
    enum class Type
    {
        RegularUser,
        Administrator
    };
    explicit User(int id = -1, const QString &name = "",
                  const QString &password ="",
                  Type type = Type::RegularUser);
    int id() const;
    void setId(int id);

    QString name() const;
    void setName(const QString &name);

    QString password() const;
    void setPassword(const QString &password);

    Type type() const;
    void setType(const Type &type);

private:
    int mId;
    QString mName;
    QString mPassword;
    Type mType;
};

#endif // USER_H
