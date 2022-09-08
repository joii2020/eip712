make clean
make all
if (( $? == 0 ))
then
  echo -e "\033[32mSuccess\033[0m"
else
  echo -e "\033[31mMake all Failed\033[0m"
  exit 2
fi

./build/test

if (( $? == 0 ))
then
  echo -e "\033[32mSuccess\033[0m"
else
  echo -e "\033[31mtest Failed\033[0m"
  exit 2
fi
