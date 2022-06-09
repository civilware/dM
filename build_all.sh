#!/usr/bin/env bash

CURDIR=`/bin/pwd`
BASEDIR=$(dirname $0)
ABSPATH=$(readlink -f $0)
ABSDIR=$(dirname $ABSPATH)


unset GOPATH

version="1.0.28"


cd $CURDIR
bash $ABSDIR/build_package.sh "github.com/civilware/dM/cmd/client-service"

#copy site contents into folders
cd "cmd/client-service"
for d in $ABSDIR/build/*; do cp -R site/. "$d/site"; done
cd "${ABSDIR}/build"

#windows users require zip files
#zip -r deromessage_windows_amd64.zip deromessage_windows_amd64
#zip -r deromessage_windows_x86.zip deromessage_windows_386
#zip -r deromessage_windows_386.zip deromessage_windows_386
zip -r deromessage_windows_amd64_$version.zip deromessage_windows_amd64
zip -r deromessage_windows_x86_$version.zip deromessage_windows_386
zip -r deromessage_windows_386_$version.zip deromessage_windows_386

#all other platforms are okay with tar.gz
#find . -mindepth 1 -maxdepth 1 -type d -not -name '*windows*'   -exec tar -cvzf {}.tar.gz {} \;
find . -mindepth 1 -maxdepth 1 -type d -not -name '*windows*'   -exec tar -cvzf {}_$version.tar.gz {} \;

cd $CURDIR
