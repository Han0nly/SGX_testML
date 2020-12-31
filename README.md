# SGX_testML
## System requirements
* OS: Ubuntu 18.04 LTS
* Intel SGX driver, PSW, SDK Version 2.12
* [LibSVM](https://github.com/arnaudsj/libsvm) Version 324
* [Fann Library](https://github.com/libfann/fann)
* [secp256k1](https://github.com/bitcoin-core/secp256k1)

### Install Intel SGX driver, PSW, SDK

If you are using ubuntu 18.04, run the following commands to install SGX development environments.
```shell
# https://download.01.org/intel-sgx/sgx-linux/2.12/distro/ubuntu18.04-server/

# driver(ECDSA)
apt-get install build-essential ocaml automake autoconf libtool wget python libssl-dev
wget - https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu18.04-server/sgx_linux_x64_driver_1.36.2.bin
chmod 777 sgx_linux_x64_driver_1.36.2.bin
./sgx_linux_x64_driver_1.36.2.bin

# SDK
wget - https://download.01.org/intel-sgx/latest/linux-latest/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.12.100.3.bin
./sgx_linux_x64_sdk_2.12.100.3.bin
source /root/sgxsdk/environment

# PSW
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
apt-get update
apt-get install libsgx-launch libsgx-urts
apt-get install libsgx-epid libsgx-urts
apt-get install libsgx-quote-ex libsgx-urts
apt install libsgx-*-dev
apt install libsgx-*-dbgsym

# The Intel® SGX PSW binary package installs the user space libraries in /usr/lib.

# The Intel® SGX PSW Debian packages install the user space libraries in /usr/lib/x86_64-linux-gnu.

# The Intel® SGX SDK package installs the corresponding shell libraries in [User Input Path]/sgxsdk/lib64.
```

### Install LibSVM
```shell
apt install libsvm-dev
```

### Install Fann
```shell
git clone https://github.com/libfann/fann.git
cd fann
cmake .
make install
```

### Install secp256k1
```
git clone https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
./autogen.sh
./configure
make
make check
make install
```

## How to compile
```shell
git clone https://github.com/Han0nly/SGX_testML.git
cd SGX_testML
make
./app
```
If you see the following messages, then it is ready to go.
```shell
$ ./app

Enclave initialized.

## CEE ## ready to roll:
Press 1: Computation task 1. (Encrypt single data file)
Press 2: Computation task 2. (Encrypt multiple data files).
Press 3: Computation task 3. (Sum from 1 to 10000 for single file) inside enclave.
Press 4: Computation task 4. (Sum from 1 to 10000 for multiple files) inside enclave.
Press 5: Computation task 5. (Sum from 1 to 10000 for multiple files) outside enclave.
Press 6: Computation task 6. (training SVM model) inside enclave.
Press 7: Computation task 7. (training SVM model) outside enclave.
Press 8: Computation task 8. (training ANN model) inside enclave.
Press 9: Computation task 9. (training ANN model) outside enclave.
Press 0: Exit.
```
## How to use
```shell
$ ./app


Enclave initialized.

## CEE ## ready to roll:
Press 1: Computation task 1. (Encrypt single data file)
Press 2: Computation task 2. (Encrypt multiple data files).
Press 3: Computation task 3. (Sum from 1 to 10000 for single file) inside enclave.
Press 4: Computation task 4. (Sum from 1 to 10000 for multiple files) inside enclave.
Press 5: Computation task 5. (Sum from 1 to 10000 for multiple files) outside enclave.
Press 6: Computation task 6. (training SVM model) inside enclave.
Press 7: Computation task 7. (training SVM model) outside enclave.
Press 8: Computation task 8. (training ANN model) inside enclave.
Press 9: Computation task 9. (training ANN model) outside enclave.
Press 0: Exit.

6
Number of files: 10
encrypt_file Completed
encrypt_file Completed
encrypt_file Completed
encrypt_file Completed
encrypt_file Completed
encrypt_file Completed
encrypt_file Completed
encrypt_file Completed
encrypt_file Completed
encrypt_file Completed

Before fopen DC_result

After fopen DC_result

Begin task 2 [training SVM classifier].

[ENCLAVE] Datafile 0's dimension: N = 300, K = 14, C = 2

[ENCLAVE] Datafile 1's dimension: N = 300, K = 14, C = 2

[ENCLAVE] Datafile 2's dimension: N = 300, K = 14, C = 2

[ENCLAVE] Datafile 3's dimension: N = 300, K = 14, C = 2

[ENCLAVE] Datafile 4's dimension: N = 300, K = 14, C = 2

[ENCLAVE] Datafile 5's dimension: N = 300, K = 14, C = 2

[ENCLAVE] Datafile 6's dimension: N = 300, K = 14, C = 2

[ENCLAVE] Datafile 7's dimension: N = 300, K = 14, C = 2

[ENCLAVE] Datafile 8's dimension: N = 300, K = 14, C = 2

[ENCLAVE] Datafile 9's dimension: N = 300, K = 14, C = 2

[ENCLAVE] Merged Data's dimension: N = 3000, K = 14, C = 2

*.
WARNING: using -h 0 may be faster
*
optimization finished, #iter = 1814
nu = 0.326003
obj = -4250.471842, rho = 0.531971
nSV = 1293, nBSV = 796
Total nSV = 1293

Average time for [training SVM classifier inside of the enclave]: 0.508546 seconds
```



