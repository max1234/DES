#include "dialog.h"
#include "ui_dialog.h"

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{   ui->setupUi(this);
    ModeIndex = 0;
    ui->textBrowser->insertPlainText(ModeNames[ModeIndex]);
    ui->VectorWidget->setEnabled(0);}
Dialog::~Dialog()
{   inputFile.close();
    keyFile.close();
    outputFile.close();
    delete ui;}
void Dialog::on_ButtonSelectInputFile_clicked()
{   QFileDialog::Options options;
    QString selectedFilter;
    inputFileName = QFileDialog::getOpenFileName(this,"Select Input File",
    ui->LabelSelectInputFile->text(), "All Files (*)",&selectedFilter,options);
    if (!inputFileName.isEmpty())
    {   ui->LabelSelectInputFile->setText(inputFileName);
        inputFile.setFileName(inputFileName);}}
void Dialog::on_ButtonSelectKeyFile_clicked()
{   QFileDialog::Options options;
    QString selectedFilter;
    keyFileName = QFileDialog::getOpenFileName(this,"Select Key File",
    ui->LabelSelectKeyFile->text(),"All Files (*)",&selectedFilter,options);
    if (!keyFileName.isEmpty())
    {   ui->LabelSelectKeyFile->setText(keyFileName);
        keyFile.setFileName(keyFileName);}}
void Dialog::on_ButtonSelectOutputFile_clicked()
{   QFileDialog::Options options;
    QString selectedFilter;
    outputFileName = QFileDialog::getSaveFileName(this,"Select Output File",
    ui->LabelSelectOutputFile->text(),"All Files (*)",&selectedFilter,options);
    if (!outputFileName.isEmpty())
    {   ui->LabelSelectOutputFile->setText(outputFileName);
        outputFile.setFileName(outputFileName);}}
void Dialog::on_ButtonSelectVectorFile_clicked()
{   QFileDialog::Options options;
    QString selectedFilter;
    vectorFileName = QFileDialog::getOpenFileName(this,"Select Vector File",
    ui->LabelSelectVectorFile->text(),"All Files (*)",&selectedFilter,options);
    if(!vectorFileName.isEmpty())
    {   ui->LabelSelectVectorFile->setText(vectorFileName);
        vectorFile.setFileName(vectorFileName);}}
void Dialog::on_quitButton_clicked()
{    QApplication::closeAllWindows();}
void Dialog::on_ButtonEncrypt_clicked()
{if(!inputFileName.isEmpty()\
     && !keyFileName.isEmpty()\
     && !outputFileName.isEmpty())
    if(inputFile.open(QIODevice::ReadOnly)\
      && keyFile.open(QIODevice::ReadOnly)\
      && outputFile.open(QIODevice::WriteOnly))
        {pinputFile = &inputFile;
         pkeyFile = &keyFile;
         poutputFile = &outputFile;
         pvectorFile = NULL;
         if(ModeIndex)
          {if(!vectorFileName.isEmpty())
            {if(vectorFile.open(QIODevice::ReadOnly))
              {pvectorFile = &vectorFile;}
                else
                {   ui->textBrowser->insertPlainText("Files open error\n");
                        exit(0);}}
                else
                {   ui->textBrowser->insertPlainText("One or more files are missing\n");
                    exit(0);}}
            DES desMetod;
            desMetod.EncryptDecryptFlag=1;
            desMetod.ModeIndex = ModeIndex;
            if(desMetod.MainDES(pinputFile, pkeyFile, poutputFile, pvectorFile))
              ui->textBrowser->insertPlainText(desMetod.ErrorStr);
            else
              ui->textBrowser->insertPlainText("Enecrypt success\n");
            inputFile.close();
            keyFile.close();
            outputFile.close();
            inputFileName="";
            keyFileName="";
            outputFileName="";
            ui->LabelSelectInputFile->setText("Select input file");
            ui->LabelSelectKeyFile->setText("Select key file");
            ui->LabelSelectOutputFile->setText("Select output file");
            if(ModeIndex)
            {   vectorFile.close();
                vectorFileName = "";
                ui->LabelSelectVectorFile->setText("Select vector file");}}
          else
            ui->textBrowser->insertPlainText("Files open error\n");
         else
          ui->textBrowser->insertPlainText("One or more files are missing\n");}
void Dialog::on_ButtonDecrypt_clicked()
{    if(!inputFileName.isEmpty()\
       && !keyFileName.isEmpty()\
       && !outputFileName.isEmpty())
      if(inputFile.open(QIODevice::ReadOnly)\
        && keyFile.open(QIODevice::ReadOnly)\
        && outputFile.open(QIODevice::WriteOnly))
        {   pinputFile = &inputFile;
            pkeyFile = &keyFile;
            poutputFile = &outputFile;
            pvectorFile = NULL;
            if(ModeIndex)
            {if(!vectorFileName.isEmpty())
             {if(vectorFile.open(QIODevice::ReadOnly))
               {pvectorFile = &vectorFile;}
               else
                {ui->textBrowser->insertPlainText("Files open error\n");
                 exit(0);}}
                else
                {ui->textBrowser->insertPlainText("One or more files are missing\n");
                 exit(0);}}
            DES desMetod;
            desMetod.EncryptDecryptFlag=0;
            desMetod.ModeIndex=ModeIndex;
            if(desMetod.MainDES(pinputFile,pkeyFile,poutputFile,pvectorFile))
                ui->textBrowser->insertPlainText(desMetod.ErrorStr);
            else
                ui->textBrowser->insertPlainText("Decrypt success\n");
            inputFile.close();
            keyFile.close();
            outputFile.close();
            inputFileName = "";
            keyFileName = "";
            outputFileName = "";
            ui->LabelSelectInputFile->setText("Select input file");
            ui->LabelSelectKeyFile->setText("Select key file");
            ui->LabelSelectOutputFile->setText("Select output file");
            if(ModeIndex)
            {   vectorFile.close();
                vectorFileName = "";
                ui->LabelSelectVectorFile->setText("Select vector file");}}
          else
          ui->textBrowser->insertPlainText("Files open error\n");
        else
        ui->textBrowser->insertPlainText("One or more files are missing\n");}
void Dialog::on_comboBox_currentIndexChanged(int index)
{   ModeIndex = index;
    ui->textBrowser->insertPlainText(ModeNames[ModeIndex]);
    if(!index)
    {ui->VectorWidget->setEnabled(0);}
    else {ui->VectorWidget->setEnabled(1);}}
