#ifndef SELECTDEVICE_H
#define SELECTDEVICE_H

#include <QDialog>
#include <QObject>
#include <QDebug>
#include <QMessageBox>
#include <pcap.h>

#define BUFSIZE 65536

namespace Ui {
class SelectDevice;
}

class SelectDevice : public QDialog
{
    Q_OBJECT

public:
    explicit SelectDevice(QWidget *parent = 0);
    ~SelectDevice();

    pcap_t* handle;
    QString deviceLabel;

private slots:
    void on_pbSelect_clicked();

    void on_pbClose_clicked();

private:
    Ui::SelectDevice *ui;

    pcap_if_t *alldevsp;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

protected:
    void findDev();
    void selectDev();

};

#endif // SELECTDEVICE_H
