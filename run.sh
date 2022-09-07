make clean
make all
if (( $? == 0 ))
then
  echo "\033[32mSuccess\033[0m"
else
  echo "\033[31mMake all Failed\033[0m"
  exit 2
fi

./build/test

if (( $? == 0 ))
then
  echo "\033[32mSuccess\033[0m"
else
  echo "\033[31mtest Failed\033[0m"
  exit 2
fi
