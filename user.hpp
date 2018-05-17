#ifndef USER_H
#define USER_H

#include <QString>

class User
{
public:
    explicit User(int id = -1, const QString &name = "",
                  const QString &password ="");
    int id() const;
    void setId(int id);

    QString name() const;
    void setName(const QString &name);

    QString password() const;
    void setPassword(const QString &password);

private:
    int mId;
    QString mName;
    QString mPassword;
};

#endif // USER_H
