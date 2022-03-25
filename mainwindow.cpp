#include <QMessageBox>

#include "mainwindow.hpp"
#include "ui_mainwindow.h"
#include "aes128.hpp"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::generateKey_button()
{
    if(!ui->keyLine->text().isEmpty())
    {
        QMessageBox::warning(this, "AES-crypter", "Key already generated.");
        return;
    }
    QString newKey;
    for (unsigned int i = 0; i < 32; i++)
    {
        QChar ch = QChar(rand());
        newKey.append(ch);
        key[i] = ch.unicode();
    }

    ui->keyLine->setText(newKey);
}

void MainWindow::encode_button()
{
    if (ui->enterText->toPlainText().isEmpty()) {
        QMessageBox::warning(this, "AES-crypter", "Enter Text is empty. Please, fill a text area.");
        return;
    }
    else if(ui->keyLine->text().isEmpty()) {
        QMessageBox::warning(this, "AES-crypter", "Key is empty. Please, click button "
                                                  "'Generate key' for encode text.");
        return;
    }

    QString text = ui->enterText->toPlainText();

    aes128 aes;
    QString output = QString::fromStdString(aes.enc(text.toStdString(), key));

    ui->finalText->setPlainText(output);
}

void MainWindow::decode_button()
{
    if (ui->enterText->toPlainText().isEmpty()) {
        QMessageBox::warning(this, "AES-crypter", "Enter Text is empty. Please, fill a text area.");
        return;
    }
    else if(ui->keyLine->text().isEmpty()) {
        QMessageBox::warning(this, "AES-crypter", "Key is empty. Please, click button "
                                                  "'Generate key' for decode text.");
        return;
    }

    QString text = ui->enterText->toPlainText();

    aes128 aes;
    QString output = QString::fromStdString(aes.dec(text.toStdString(), key));

    ui->finalText->setPlainText(output);
}

void MainWindow::flip_button()
{
    ui->enterText->setPlainText(ui->finalText->toPlainText());
    ui->finalText->clear();
}
