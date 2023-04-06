#include <QCoreApplication>
#include "dhke.h"
#include <QDebug>
#include <QFile>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    DHKE dhke;
    dhke.setEngine("tpm2tss");

    return a.exec();
}
