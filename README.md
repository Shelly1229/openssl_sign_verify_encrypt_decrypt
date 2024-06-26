# openssl_sign_verify_encrypt_decrypt
This is a program that implements authentication and key management. It includes RSA algorithm(C++/Python), a hybrid algorithm that combines ECDSA and AES(C++) and a hybrid algorithm that combines DES and DSA(Python). 

c++_openssl includes two algorithms(RSA and ECDSA_AES) to authenticate, encrypt and decrypt string information, and calculate runtime.

c++_openssl_json includes two algorithms(RSA and ECDSA_AES) to authenticate, encrypt and decrypt json information, and calculate runtime.

python_rsa_dsa_des includes two algorithms(RSA and DSA_DES) to authenticate, encrypt and decrypt json information, and calculate runtime.

running environment:Linux

language:C++,Python

# Running C++ program
## install C++ dependencies
sudo apt-get install make

sudo apt-get install g++

sudo apt-get install gdb

sudo apt-get install git

sudo apt-get install wget

## Install the openssl dependency package
sudo wget --no-check-certificate https://www.openssl.org/source/openssl-1.1.1w.tar.gz

tar -xvf openssl-1.1.1w.tar.gz

cd openssl-1.1.1w

./config

make -j32

sudo make install


## xftp or other file transfer tools transfer files to Linux systems
sudo apt install net-tools

sudo apt-get install openssh-server


## Install json dependency packages
sudo apt install -y libjsoncpp-dev

sudo ln -s /usr/include/jsoncpp/json/ /usr/local/include/json


## Debug code
cd openssl_rsa

make

./rsa


cd openssl_ecdsa_aes

make

./new

# Running Python program
python rsa.py

python dsa+des.py


