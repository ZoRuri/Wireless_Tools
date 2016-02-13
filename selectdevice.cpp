#include "selectdevice.h"
#include "ui_selectdevice.h"

SelectDevice::SelectDevice(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SelectDevice)
{
    ui->setupUi(this);

    handle = NULL;
    findDev();
}

SelectDevice::~SelectDevice()
{
    delete ui;
}

void SelectDevice::findDev()
{
        pcap_findalldevs(&alldevsp, errbuf);

        for(dev = alldevsp; dev ; dev = dev->next)
        {
            ui->listWidget->addItem(dev->name);
        }

        pcap_freealldevs(alldevsp);
}

void SelectDevice::selectDev()
{

//    QListWidgetItem *qListWidgetItem = new QListWidgetItem(ui->listWidget);
//    qListWidgetItem = ui->listWidget->currentItem();

//    const char* devHandle = qListWidgetItem->text().toStdString().c_str();
    const char* devHandle = ui->listWidget->currentItem()->text().toStdString().c_str();
    deviceLabel = ui->listWidget->currentItem()->text();


    if (devHandle != NULL) {
        handle = pcap_open_live(devHandle, BUFSIZE, 1, 1000, errbuf);
        qDebug() << devHandle;
        qDebug() << deviceLabel;
        qDebug() << handle;
        this->close();
    }
    else {
        QMessageBox::critical(this, "Error", "Can't open your device", "Close");
    }

}

void SelectDevice::on_pbSelect_clicked()
{
    selectDev();
}

void SelectDevice::on_pbClose_clicked()
{
   this->close();
}
