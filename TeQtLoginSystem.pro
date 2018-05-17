#-------------------------------------------------
#
# Project created by QtCreator 2018-05-16T16:39:11
#
#-------------------------------------------------

QT       += core gui sql
CONFIG += c++1z static

INCLUDEPATH += /usr/local/ssl/include
LIBS += /usr/local/ssl/lib/libssl.a
LIBS += /usr/local/ssl/lib/libcrypto.a
LIBS += -ldl

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = TeQtLoginSystem
TEMPLATE = app


SOURCES += main.cpp\
        dialog.cpp \
    tecipher.cpp \
    registerAdminDialog.cpp \
    user.cpp \
    admin.cpp \
    dbmanager.cpp

HEADERS  += dialog.hpp \
    tecipher.hpp \
    registerAdminDialog.hpp \
    user.hpp \
    admin.hpp \
    dbmanager.hpp

FORMS    += dialog.ui \
    registerAdminDialog.ui
