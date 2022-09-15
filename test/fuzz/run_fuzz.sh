CUR_DIR=$(dirname $(readlink -f "$0"))

cd $CUR_DIR

rm -rf fuzz_eip712
make
if (( $? == 0 ))
then
  echo -e "\033[32mSuccess\033[0m"
else
  echo -e "\033[31mMake all Failed\033[0m"
  exit 2
fi

cd $CUR_DIR/build

$CUR_DIR/build/fuzz_eip712 -jobs=30 -max_len=33
