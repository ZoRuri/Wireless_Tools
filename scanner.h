#ifndef SCANNER_H
#define SCANNER_H

#include <pcap.h>
#include <arpa/inet.h>
#include <QThread>
#include <QObject>

#include "selectdevice.h"

#pragma pack(push, 1)
struct CaptureInfo
{
    QString BSSID;
    QString SSID;
    QString Encryption;

    int Channel;

    QString STA;
    QString AP;

    int chkType;
};
#pragma pack(pop)

class Scanner : public QObject
{
    Q_OBJECT

public:
    explicit Scanner(QObject *parent = 0);

    bool status;
    int channel;

    void getHandle(pcap_t *);

private:
    SelectDevice selectDevice;

    struct pcap_pkthdr* pkthdr;
    pcap_t* scannerHandle;
    const u_char* data;

    void channelLoop();

public slots:
    void start();
    void stop();

signals:
    void captured(CaptureInfo captureInfo);
};

#endif // SCANNER_H
