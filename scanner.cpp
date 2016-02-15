#include "scanner.h"

Scanner::Scanner(QObject *parent) : QObject(parent)
{
    status = false;
}

void Scanner::getHandle(pcap_t* handle)
{
    scannerHandle = handle;
}

void Scanner::start()
{
    qDebug() << "scanner" << scannerHandle;

    while(status)
    {
        int SSIDlen;
        int res = pcap_next_ex(scannerHandle, &pkthdr, &data);
        if (res == 0) continue;
        if (res < 0) break;

        CaptureInfo captureInfo;

        int i = 0;

        QByteArray temp;

        int SIZE_RADIOTAB = *(data+2);

        if ( ntohs(*(data+SIZE_RADIOTAB)) == 0x8000 && (data[SIZE_RADIOTAB+4] == 0xff && data[SIZE_RADIOTAB+5] == 0xff && data[SIZE_RADIOTAB+6] == 0xff && data[SIZE_RADIOTAB+7] == 0xff && data[SIZE_RADIOTAB+8] == 0xff && data[SIZE_RADIOTAB+9] == 0xff )) // Only Beacon frame && Broadcast
        {
            captureInfo.BSSID.sprintf("%02X:%02X:%02X:%02X:%02X:%02X",*(data+SIZE_RADIOTAB+16), *(data+SIZE_RADIOTAB+17), *(data+SIZE_RADIOTAB+18), *(data+SIZE_RADIOTAB+19), *(data+SIZE_RADIOTAB+20), *(data+SIZE_RADIOTAB+21));

            for(SSIDlen=0;SSIDlen<data[SIZE_RADIOTAB+37];++SSIDlen)
            {
                if(127 < *(data+SIZE_RADIOTAB+38+SSIDlen)){
                    temp.append(*(data+SIZE_RADIOTAB+38+SSIDlen));
                    ++i;
                    if (i == 3) {
                        captureInfo.SSID.append(temp);
                        qDebug() << captureInfo.SSID;
                        temp.clear();
                        i = 0;
                    }
                }
                else
                    captureInfo.SSID.append(*(data+SIZE_RADIOTAB+38+SSIDlen));
            }

            SSIDlen = data[SIZE_RADIOTAB+37];

            int SR = *(data+SIZE_RADIOTAB+38+SSIDlen+1)+2; // Supported Rates

            captureInfo.Channel = *(data+SIZE_RADIOTAB+38+SSIDlen+SR+2);

            int TIM = *(data+SIZE_RADIOTAB+38+SSIDlen+SR+4)+2; // Traffic Indication Map

            int pointed = (SIZE_RADIOTAB+38+SSIDlen+SR+TIM);

            if (!((*(data+SIZE_RADIOTAB+34)) & 16))
                captureInfo.Encryption = "OPEN";
            else {
                while (pointed < (int)pkthdr->len) {
                    if (*(data+pointed) == 0x30) {
                        if (*(data+pointed + 4) == 0x00 && *(data+pointed + 5) == 0x0f && *(data+pointed + 6) == 0xac) { // WPA2
                            switch (*(data+pointed + 7))// Encrpytion check
                            {
                                case 0x01:
                                    captureInfo.Encryption = "WEP";
                                    break;
                                case 0x02:
                                    captureInfo.Encryption = "WPA2-TKIP";
                                    break;
                                case 0x03:
                                    captureInfo.Encryption = "WPA2-WRAP";
                                    break;
                                case 0x04:
                                    captureInfo.Encryption = "WPA2-AES";
                                    break;
                                case 0x05:
                                    captureInfo.Encryption = "WPA2-WEP104";
                                    break;
                            }
                                break;
                        }
                        pointed += *(data+pointed+1);
                    }
                    else if (*(data+pointed) == 0xdd) {
                        if (*(data+pointed + 2) == 0x00 && *(data+pointed + 3) == 0x50 && *(data+pointed + 4) == 0xf2) { // WPA1
                            switch (*(data+pointed + 5))// Encrpytion check
                            {
                                case 0x01:
                                    captureInfo.Encryption = "WEP";
                                    break;
                                case 0x02:
                                    captureInfo.Encryption = "WPA-TKIP";
                                    break;
                                case 0x03:
                                    captureInfo.Encryption = "WPA-WRAP";
                                    break;
                                case 0x04:
                                    captureInfo.Encryption = "WPA-AES";
                                    break;
                                case 0x05:
                                    captureInfo.Encryption = "WPA-WEP104";
                                    break;
                            }
                            break;
                        }
                    }
                    ++pointed;
                }
            }
            captureInfo.chkType = 0;
            emit captured(captureInfo);
        }
        else if((*(data+SIZE_RADIOTAB) & 8) && !(*(data+SIZE_RADIOTAB) & 64)) {       // Data frame AND not NULL Data
            if(*(data+SIZE_RADIOTAB) & 128) { // QoS Data
                switch ((*(data+SIZE_RADIOTAB+1) & 3))    // check DS
                {
                    case 0x01: // To DS 01     STA -> AP   BSSID - Src - Des
                        captureInfo.BSSID.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", data[SIZE_RADIOTAB+4], data[SIZE_RADIOTAB+5], data[SIZE_RADIOTAB+6], data[SIZE_RADIOTAB+7], data[SIZE_RADIOTAB+8], data[SIZE_RADIOTAB+9]);
                        captureInfo.STA.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", data[SIZE_RADIOTAB+10], data[SIZE_RADIOTAB+11], data[SIZE_RADIOTAB+12], data[SIZE_RADIOTAB+13], data[SIZE_RADIOTAB+14], data[SIZE_RADIOTAB+15]);
                        captureInfo.AP.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", data[SIZE_RADIOTAB+16], data[SIZE_RADIOTAB+17], data[SIZE_RADIOTAB+18], data[SIZE_RADIOTAB+19], data[SIZE_RADIOTAB+20], data[SIZE_RADIOTAB+21]);
                        break;
                    case 0x02: // From DS 10   AP -> STA   Des - BSSID - Src
                        captureInfo.BSSID.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", data[SIZE_RADIOTAB+10], data[SIZE_RADIOTAB+11], data[SIZE_RADIOTAB+12], data[SIZE_RADIOTAB+13], data[SIZE_RADIOTAB+14], data[SIZE_RADIOTAB+15]);
                        captureInfo.AP.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", data[SIZE_RADIOTAB+16], data[SIZE_RADIOTAB+17], data[SIZE_RADIOTAB+18], data[SIZE_RADIOTAB+19], data[SIZE_RADIOTAB+20], data[SIZE_RADIOTAB+21]);
                        captureInfo.STA.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", data[SIZE_RADIOTAB+4], data[SIZE_RADIOTAB+5], data[SIZE_RADIOTAB+6], data[SIZE_RADIOTAB+7], data[SIZE_RADIOTAB+8], data[SIZE_RADIOTAB+9]);
                        break;
                }
            }
            else {
                switch ((*(data+SIZE_RADIOTAB+1) & 3))    // check DS
                {
//                    case 0x01: // To DS 01     STA -> AP   BSSID - Src - Des
//                        captureInfo.BSSID.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", data[SIZE_RADIOTAB+4], data[SIZE_RADIOTAB+5], data[SIZE_RADIOTAB+6], data[SIZE_RADIOTAB+7], data[SIZE_RADIOTAB+8], data[SIZE_RADIOTAB+9]);
//                        captureInfo.STA.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", data[SIZE_RADIOTAB+10], data[SIZE_RADIOTAB+11], data[SIZE_RADIOTAB+12], data[SIZE_RADIOTAB+13], data[SIZE_RADIOTAB+14], data[SIZE_RADIOTAB+15]);
//                        captureInfo.AP.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", data[SIZE_RADIOTAB+16], data[SIZE_RADIOTAB+17], data[SIZE_RADIOTAB+18], data[SIZE_RADIOTAB+19], data[SIZE_RADIOTAB+20], data[SIZE_RADIOTAB+21]);
//                        break;
                    case 0x02: // From DS 10   AP -> STA   Des - BSSID - Src
                        captureInfo.BSSID.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", data[SIZE_RADIOTAB+10], data[SIZE_RADIOTAB+11], data[SIZE_RADIOTAB+12], data[SIZE_RADIOTAB+13], data[SIZE_RADIOTAB+14], data[SIZE_RADIOTAB+15]);
                        captureInfo.STA.sprintf("%02X:%02X:%02X:%02X:%02X:%02X", data[SIZE_RADIOTAB+16], data[SIZE_RADIOTAB+17], data[SIZE_RADIOTAB+18], data[SIZE_RADIOTAB+19], data[SIZE_RADIOTAB+20], data[SIZE_RADIOTAB+21]);
//                        captureInfo..sprintf("%02X:%02X:%02X:%02X:%02X:%02X", data[SIZE_RADIOTAB+4], data[SIZE_RADIOTAB+5], data[SIZE_RADIOTAB+6], data[SIZE_RADIOTAB+7], data[SIZE_RADIOTAB+8], data[SIZE_RADIOTAB+9]);
                        break;
                }
            }

            if (captureInfo.STA.contains(QRegExp("^01:00:5E")) || captureInfo.STA.contains(QRegExp("^33:33")) || captureInfo.STA.contains("FF:FF:FF:FF:FF:FF"))
                return;

            qDebug() << "find data" ;
            captureInfo.chkType = 1;
            emit captured(captureInfo);
        }

    }

}

void Scanner::stop()
{
    this->status = false;
}
