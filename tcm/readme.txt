1.run bash ./env.sh
2.install  driver
  cd \Driver\AX99100_SPI
  make
  sudo insmode ax99100_spi.ko
  and you will find spi0 with ls /dev
2. use libftddl.so if 32 bit os version
    use libftddl_64.so with name libftddl.so if 64 bit os version
    Sugggestion:re-compile libftddl on you platform
3.compile the tool
   cd tcmlib
   make
4. copy /out/test_getcapability to ../out/test_getcapability
5. run sudo ./test_getcapability

