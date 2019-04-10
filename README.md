# mbedtls-tomcrypt

To pull the submodules :

```bash
git submodule update --init --recursive
```

To configure MBEDTLS :

```bash
cd mbedtls
git apply ../mbedtls.diff
```

To configure openssl :

```bash
cd openssl
./config
make
```

To build :

```bash
mkdir build
cd build
cmake ..
make
```

The binaries need to be ran at the root of the project. There are located in bin/.