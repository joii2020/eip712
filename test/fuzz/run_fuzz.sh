CUR_DIR=$(dirname $(readlink -f "$0"))

cd $CUR_DIR

make clean
mkdir -p build
make all
if (( $? == 0 ))
then
  echo -e "\033[32mSuccess\033[0m"
else
  echo -e "\033[31mMake all Failed\033[0m"
  exit 2
fi

cd $CUR_DIR

$CUR_DIR/build/fuzz_eip712 -jobs=4
# $CUR_DIR/build/fuzz_eip712_2
