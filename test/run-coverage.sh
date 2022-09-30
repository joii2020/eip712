
make clean
make ENABLE_RVV=0 ENABLE_COVERAGE=1

lcov -c -i -d ./ -o init.info

./build/test

lcov -c -d ./ -o cover.info
lcov -a init.info -a cover.info -o total.info
lcov --remove total.info '*/usr/include/*' '*/usr/lib/*' '*/usr/lib64/*' '*/usr/local/include/*' '*/usr/local/lib/*' '*/usr/local/lib64/*' '*/third/*' 'testa.cpp' -o final.info
genhtml -o cover_report --legend --title "lcov"  --prefix=./ final.info

