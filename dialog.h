#ifndef DIALOG_H
#define DIALOG_H

#define NUMBER_MODES 4
#include <QDialog>
#include <QWidget>
#include <QtGui>
#include "des.h"

namespace Ui
{class Dialog;}
class Dialog:public QDialog
{    Q_OBJECT
    public:
    explicit Dialog(QWidget *parent = 0);
    ~Dialog();
    QString inputFileName;  QString keyFileName;
    QString outputFileName; QString vectorFileName;
    QFile inputFile;        QFile keyFile;
    QFile outputFile;       QFile vectorFile;
    QFile *pinputFile;      QFile *pkeyFile;
    QFile *poutputFile;     QFile *pvectorFile;
    int ModeIndex;
private slots:
    void on_ButtonSelectInputFile_clicked();
    void on_ButtonSelectKeyFile_clicked();
    void on_ButtonSelectOutputFile_clicked();
    void on_ButtonSelectVectorFile_clicked();
    void on_quitButton_clicked();
    void on_ButtonEncrypt_clicked();
    void on_ButtonDecrypt_clicked();
    void on_comboBox_currentIndexChanged(int index);
private:
    Ui::Dialog *ui;};
const QString ModeNames[NUMBER_MODES]=
{"Electronic CodeBook mode\n",\
 "Cipher Block Chaining mode\n",\
 "Cipher Feed Back mode\n",\
 "Output Feed Back mode\n"};
#endif
