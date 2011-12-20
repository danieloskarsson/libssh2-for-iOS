# libssh2 for iOS

## Purpose
The purpose of this project is to get ssh port forward working on a standard (i.e. NOT a jailbreaked phone).

## Libraries
To accomplish this libssh2 with openssl support is compiled for armv6, armv7 and i386 (simulator) and merged into static libraries (.a files).

## Enhancements
This project is forked from https://github.com/x2on/libssh2-for-iOS. Additional features are that the build scripts are updated for iOS 5.0 and the latest version of Xcode, support for keyboard-interactive as by https://github.com/gonzopancho/libssh2-for-iOS/, and port forward as in http://www.libssh2.org/examples/direct_tcpip.html.