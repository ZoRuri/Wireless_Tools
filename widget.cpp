#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);

    QObject::connect(&scannerThread, SIGNAL(started()), &scanner, SLOT(start()));
    QObject::connect(&scannerThread, SIGNAL(finished()), &scanner, SLOT(stop()));

    QObject::connect(&scanner, SIGNAL(captured(CaptureInfo)), this, SLOT(setCaptureInfo(CaptureInfo)), Qt::BlockingQueuedConnection);

    QObject::connect(&channelThread, SIGNAL(started()), &timer, SLOT(start()));
    QObject::connect(&timer, SIGNAL(timeout()), this, SLOT(channelLoop()));
    QObject::connect(&channelThread, SIGNAL(finished()), &timer, SLOT(stop()));

}

Widget::~Widget()
{
    delete ui;
}

void Widget::on_pbSelectDevice_clicked()
{
    selectDevice.setModal(true);
    selectDevice.exec();

    ui->label_Device->setText(QString("Device : %1").arg(QString(selectDevice.deviceLabel)));
}

void Widget::on_pbStart_clicked()
{
    qDebug() << "start: " << selectDevice.deviceLabel;

    if (selectDevice.handle == NULL)
        QMessageBox::critical(this, "Error", "Please select device", "Close");
    else if (scanner.status == true)
        QMessageBox::critical(this, "Error", "It's already started", "Close");
    else {
        scanner.status = true;
        scanner.moveToThread(&scannerThread);
        scannerThread.start();
        scanner.getHandle(selectDevice.handle);

        timer.setInterval(1300);
        timer.moveToThread(&channelThread);
        channelThread.start();

        ui->label_Status->setText("Status : Running");

        channel = 1;

        sprintf(command, "iwconfig %s channel %d", selectDevice.deviceLabel.toStdString().c_str(), channel);
        system(command);

        ui->label_Channel->setText(QString("Channel : %1").arg(channel));
    }

}

void Widget::on_pbStop_clicked()
{
    channelThread.quit();
    channelThread.wait();
    qDebug() << "channelThread stop";

    scanner.status = false;
    qDebug() << "scannerThread status";
    scannerThread.quit();
    qDebug() << "scannerThread quit";
    scannerThread.wait();
    qDebug() << "scannerThread stop";

    ui->label_Status->setText("Status : Stopped");
}

void Widget::setCaptureInfo(CaptureInfo captureInfo)
{
    QList<QTreeWidgetItem *> chk_BSSID_Overlap = ui->treeWidget->findItems(captureInfo.BSSID, Qt::MatchExactly, 5);    // BSSID Overlap check

    switch (captureInfo.chkType)    // Check Frame Type
    {
        case Beacon_Frame:
            if(chk_BSSID_Overlap.count() == 0) {   // NEW BSSID

                QTreeWidgetItem* infoTreeWidget = new QTreeWidgetItem(ui->treeWidget);

                infoTreeWidget->setText(0, captureInfo.SSID);
                infoTreeWidget->setText(1, QString::number(0));
                infoTreeWidget->setText(2, QString::number(captureInfo.Channel));
                infoTreeWidget->setText(3, captureInfo.Encryption);
                infoTreeWidget->setText(4, QString::number(0));
                infoTreeWidget->setText(5, captureInfo.BSSID);
            }
            break;

        case Data_Frame:
            if(chk_BSSID_Overlap.count() >= 1) {    // OLD BSSID

                QList<QTreeWidgetItem *> chk_STA_Overlap = ui->treeWidget->findItems(captureInfo.STA, Qt::MatchRecursive, 5);   // STA Overlap check
                QTreeWidgetItem* findedItem = chk_BSSID_Overlap[0];

                if(chk_STA_Overlap.count() == 0) {   // NEW STA

                    QTreeWidgetItem* infoSTA = new QTreeWidgetItem(findedItem);

                    infoSTA->setText(0, QString("STA %1").arg(findedItem->childCount()));
                    infoSTA->setText(1, "-");
                    infoSTA->setText(2, "-");
                    infoSTA->setText(3, "-");
                    infoSTA->setText(4, QString::number(1));
                    infoSTA->setText(5, captureInfo.STA);

                    findedItem->setText(1, QString::number(findedItem->childCount()));

                    int AP_DATA = findedItem->text(4).toInt() + 1;
                    findedItem->setText(4, QString::number(AP_DATA));
                }
                else {  // OLD STA

                    QTreeWidgetItem* infoSTA = chk_STA_Overlap[0];
                    int STA_DATA = infoSTA->text(4).toInt() + 1;
                    infoSTA->setText(4, QString::number(STA_DATA));

                    int AP_DATA = findedItem->text(4).toInt() + 1;
                    findedItem->setText(4, QString::number(AP_DATA));
                }

            }

            break;
    }

}

void Widget::channelLoop()
{
    ui->label_Channel->setText(QString("Channel : %1").arg(channel));

    sprintf(command, "iwconfig %s channel %d", selectDevice.deviceLabel.toStdString().c_str(), channel);
    system(command);

    channel += 6;

    if (channel > 14)
        channel = channel % 6 + 1;
}

void Widget::on_pbClear_clicked()
{
    while (int i = ui->treeWidget->topLevelItemCount())
    {
        delete ui->treeWidget->topLevelItem(i - 1);
    }
}
