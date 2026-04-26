sudo pkill -9 -f python
sudo systemctl stop bluetooth
sudo rfkill block bluetooth
sleep 1
sudo rfkill unblock bluetooth
sleep 1
sudo hciconfig hci0 up
sudo hciconfig hci0 down