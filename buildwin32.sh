#!/bin/sh
mingw64 ./configure --host=x86_64-w64-mingw32 --prefix=/usr/x86_64-w64-mingw32/ --with-boost-system=boost_system-mt-s --with-boost-filesystem=boost_filesystem-mt-s \
 --with-boost-program-options=boost_program_options-mt-s -with-boost-thread=boost_thread_win32-mt-s --with-boost-chrono=boost_chrono-mt-s \
 --with-boost-unit-test-framework=boost_unit_test_framework-mt-s --with-qt-incdir=/usr/x86_64-w64-mingw32/include/ --with-qt-libdir=/usr/x86_64-w64-mingw32/lib/

