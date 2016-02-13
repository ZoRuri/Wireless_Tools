#-------------------------------------------------
#
# Project created by QtCreator 2016-01-31T23:12:12
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = Wireless_Tools
TEMPLATE = app

LIBS += -lpcap

SOURCES += main.cpp\
        widget.cpp \
    selectdevice.cpp \
    scanner.cpp

HEADERS  += widget.h \
    selectdevice.h \
    scanner.h

FORMS    += widget.ui \
    selectdevice.ui
