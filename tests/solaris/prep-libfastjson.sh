# /bin/bash
set -e
set -o xtrace
PWD_HOME=$PWD
mkdir local_env
mkdir local_env/install
cd local_env
pwd
git clone git://github.com/rsyslog/libfastjson
cd libfastjson
autoreconf -fvi
./configure --prefix=$PWD_HOME/local_env/install
gmake
gmake install
pwd
ls ../install
