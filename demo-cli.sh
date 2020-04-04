#! /bin/sh

#open fifo for writing
cat > democli &

#wait then run command
sleep 5
echo hmac 5123 > democli