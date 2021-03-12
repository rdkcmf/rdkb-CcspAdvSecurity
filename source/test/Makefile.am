AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER

AM_CPPFLAGS = -Wall -g -Werror
AM_CXXFLAGS = -std=c++11

ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS = CcspAdvSecuritySsp_gtest.bin
CcspAdvSecuritySsp_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest -I${top_srcdir}/gtest/include -I${top_srcdir}/source -I${top_srcdir}/source/include
CcspAdvSecuritySsp_gtest_bin_SOURCES =  CcspAdvSecuritySspTest.cpp\
                                        gtest_main.cpp
CcspAdvSecuritySsp_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov -pthread