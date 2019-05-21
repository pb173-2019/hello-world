# Hello, world!


What do I download?
-------------------
C++ based instant communication app. The **master** branch contains windows/linux friendly basic functionality, whereas **terminal** branch contains linux-only command line cosmetic upgrades.

Known Errors
------------
The TCP will divide bigger messages into multiple segments - dependent on MSS (maximum segment size). In such case, encryption fails as it tries to encrypt only parts of the request sent to the server (e.g. both messages violates the integrity validation).
The basic ASCII for usernames are allowed, as the QString will not handle the other encodings well. This is due to usernames usage for maps and other user identification - which could use the user ID instead. To support other encodings, all the username usage will have to be replaced with IDs.

Prerequisites
-------------
QT Core library is required for the project to run. This is not auto-configurable, you need to do it yourself, as the project is closed source and available only from the QT website. If you don't have QT, download it from https://www.qt.io/download . You will need only pre-compied core library bundle for qt-supported toolchain, in dropdown menu of **Qt <version>** (either MSVC or MinGW).

Build
-----
After you succesfully downloaded precompiled QT Core library for toolchain of your choice, follow the usual scenario:

- `git clone https://github.com/pb173-2019/hello-world.git`
- `cd hello-world`
- `git submodule init`
- `git submodule update`
- `mkdir build && cd build`
- `cmake ..`
- `make`

Precompiled binaries
--------------------
We will provide precompiled binaries for both Windows and Linux in a few days.
