#!/bin/bash
sudo dpkg -i *.deb
sudo apt install -y build-essential make gcc g++ yasm  python libprotobuf10 flex bison automake
sudo apt install -y ccache cmake ccache autoconf texinfo libgcrypt20-dev libgnutls28-dev libtool pkg-config
