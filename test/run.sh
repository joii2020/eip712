make clean
# make
make all-via-docker
if (( $? == 0 ))
then
  echo -e "\033[32mSuccess\033[0m"
else
  echo -e "\033[31mMake Failed\033[0m"
  exit 2
fi

ckb-debugger --bin build/test
if (( $? == 0 ))
then
  echo -e "\033[32mSuccess\033[0m"
else
  echo -e "\033[31mRun Failed\033[0m"
  exit 2
fi