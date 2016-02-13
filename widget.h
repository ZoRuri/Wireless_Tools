#ifndef WIDGET_H
#define WIDGET_H

#include <QMainWindow>
#include <arpa/inet.h>
#include <pcap.h>
#include <QThread>
#include <QTimer>
#include <QDebug>

#include "selectdevice.h"
#include "scanner.h"

enum Frame_Type {
    Beacon_Frame,
    Data_Frame,
};

namespace Ui {
class Widget;
}

class Widget : public QMainWindow
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();

private slots:
    void on_pbSelectDevice_clicked();

    void on_pbStart_clicked();

    void on_pbStop_clicked();

    void setCaptureInfo(CaptureInfo captureInfo);

    void channelLoop();

private:
    Ui::Widget *ui;

    SelectDevice selectDevice;

    Scanner scanner;
    QThread scannerThread;

    QTimer timer;
    QThread channelThread;

    int channel = 1;
};

#endif // WIDGET_H
