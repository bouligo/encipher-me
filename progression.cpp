#include "progression.h"
#include "ui_progression.h"

Progression::Progression(QString text, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Progression)
{
    ui->setupUi(this);
    this->setWindowTitle(text);
    this->setWindowModality(Qt::ApplicationModal);
}

Progression::~Progression()
{
    delete ui;
}

void Progression::on_buttonBox_clicked(QAbstractButton *button)
{
    ui->label->setText("Annulation en cours...");
    ui->buttonBox->setEnabled(false);
    emit canceled();
}

void Progression::setCurrentProgression(int value) {
    ui->currentProgressBar->setValue(value);
}

void Progression::setCurrentNumberOfFiles(int value) {
    ui->totalProgressBar->setValue(value);
}

void Progression::setTotalNumberOfFiles(int value) {
    ui->totalProgressBar->setMaximum(value);
}

void Progression::setLabelText(QString step) {
    ui->label->setText(step);
}
