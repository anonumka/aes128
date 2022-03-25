#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

public slots:
    void generateKey_button();
    void encode_button();
    void decode_button();
    void flip_button();

private:
    Ui::MainWindow *ui;
    uint8_t key[32];
};
#endif // MAINWINDOW_HPP
