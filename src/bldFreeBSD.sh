#!/usr/local/bin/bash -v

export BOOST_INCLUDE_PATH=/usr/local/include
export BDB_INCLUDE_PATH=/usr/local/include/db48
export BOOST_LIB_PATH=/usr/local/lib
export BDB_LIB_PATH=/usr/local/lib/db48
#OPENSSL_LIB_PATH
gmake -f  makefile.FreeBSD

