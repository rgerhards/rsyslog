# /bin/bash
set -e
set -o xtrace
PWD_HOME=$PWD
alias make=gmake
mkdir local_env
mkdir local_env/bin
mkdir local_env/install
echo "gmake" > local_env/bin/make
chmod +x local_env/bin/make
PATH="$PATH:$PWD/local_env/bin"
cd local_env
pwd
git clone git://github.com/rsyslog/libfastjson
cd libfastjson
autoreconf -fvi
cat ./configure
./configure --prefix=$PWD_HOME/local_env/install
gmake
gmake install
pwd
ls ../install
