#-------------------------------------------------
#
# Project created by QtCreator 2013-12-30T21:02:47
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = encipher-me
TEMPLATE = app

CONFIG += crypto

SOURCES += main.cpp\
        mainwindow.cpp \
    Cipher.cpp

HEADERS  += mainwindow.h \
    Cipher.h

FORMS    += mainwindow.ui
