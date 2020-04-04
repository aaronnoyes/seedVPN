#! /bin/sh

mkfifo democli

sudo ./client -s 10.0.2.6 -t 10.0.4.1 -d < democli
