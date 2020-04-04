#! /bin/sh

mkfifo democli
cat > democli &

sudo ./client -s 10.0.2.6 -t 10.0.4.1 -d < democli &

sleep 5
echo hmac 5123 > democli