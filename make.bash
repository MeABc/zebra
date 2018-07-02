#!/bin/bash

set -ex

REVSION=$(git rev-list --count HEAD)
LDFLAGS="-s -w -X main.version=r${REVSION}"

GOOS=${GOOS:-$(go env GOOS)}
GOARCH=${GOARCH:-$(go env GOARCH)}
CGO_ENABLED=${CGO_ENABLED:-$(go env CGO_ENABLED)}

REPO=$(git rev-parse --show-toplevel)
PACKAGE=$(basename "${REPO}")
if [ "${CGO_ENABLED}" = "0" ]; then
  BUILDROOT=${REPO}/build/${GOOS}_${GOARCH}
else
  BUILDROOT=${REPO}/build/${GOOS}_${GOARCH}_cgo
fi
STAGEDIR=${BUILDROOT}/stage
OBJECTDIR=${BUILDROOT}/obj
DISTDIR=${BUILDROOT}/dist

if [ "${GOOS}" == "windows" ]; then
  ZEBRA_EXE="${PACKAGE}.exe"
  ZEBRA_STAGEDIR="${STAGEDIR}"
  ZEBRA_DISTCMD="7za a -y -mx=9 -m0=lzma -mfb=128 -md=64m -ms=on"
  ZEBRA_DISTEXT=".7z"
elif [ "${GOOS}" == "darwin" ]; then
  ZEBRA_EXE="${PACKAGE}"
  ZEBRA_STAGEDIR="${STAGEDIR}"
  ZEBRA_DISTCMD="env BZIP=-9 tar cvjpf"
  ZEBRA_DISTEXT=".tar.bz2"
elif [ "${GOARCH:0:3}" == "arm" ]; then
  ZEBRA_EXE="${PACKAGE}"
  ZEBRA_STAGEDIR="${STAGEDIR}"
  ZEBRA_DISTCMD="env BZIP=-9 tar cvjpf"
  ZEBRA_DISTEXT=".tar.bz2"
elif [ "${GOARCH:0:4}" == "mips" ]; then
  ZEBRA_EXE="${PACKAGE}"
  ZEBRA_STAGEDIR="${STAGEDIR}"
  ZEBRA_DISTCMD="env GZIP=-9 tar cvzpf"
  ZEBRA_DISTEXT=".tar.gz"
else
  ZEBRA_EXE="${PACKAGE}"
  ZEBRA_STAGEDIR="${STAGEDIR}/${PACKAGE}"
  ZEBRA_DISTCMD="env XZ_OPT=-9 tar cvJpf"
  ZEBRA_DISTEXT=".tar.xz"
fi

ZEBRA_DIST=${DISTDIR}/${PACKAGE}_${GOOS}_${GOARCH}-r${REVSION}${ZEBRA_DISTEXT}
if [ "${CGO_ENABLED}" = "1" ]; then
  ZEBRA_DIST=${DISTDIR}/${PACKAGE}_${GOOS}_${GOARCH}_cgo-r${REVSION}${ZEBRA_DISTEXT}
fi

ZEBRA_GUI_EXE=${REPO}/assets/taskbar/${GOARCH}/zebra-gui.exe
if [ ! -f "${ZEBRA_GUI_EXE}" ]; then
  ZEBRA_GUI_EXE=${REPO}/assets/packaging/zebra-gui.exe
fi

OBJECTS=${OBJECTDIR}/${ZEBRA_EXE}

SOURCES="${REPO}/README.md \
        ${REPO}/assets/packaging/gae.user.json.example \
        ${REPO}/httpproxy/filters/auth/auth.json \
        ${REPO}/httpproxy/filters/autoproxy/china_domain_list.txt \
        ${REPO}/httpproxy/filters/autoproxy/china_ip_list.txt \
        ${REPO}/httpproxy/filters/autoproxy/autoproxy.json \
        ${REPO}/httpproxy/filters/autoproxy/gfwlist.txt \
        ${REPO}/httpproxy/filters/autoproxy/ip.html \
        ${REPO}/httpproxy/filters/autorange/autorange.json \
        ${REPO}/httpproxy/filters/direct/direct.json \
        ${REPO}/httpproxy/filters/gae/gae.json \
        ${REPO}/httpproxy/filters/php/php.json \
        ${REPO}/httpproxy/filters/rewrite/rewrite.json \
        ${REPO}/httpproxy/filters/stripssl/stripssl.json \
        ${REPO}/httpproxy/httpproxy.json"

if [ "${GOOS}" = "windows" ]; then
  SOURCES="${SOURCES} \
             ${ZEBRA_GUI_EXE} \
             ${REPO}/assets/packaging/addto-startup.vbs \
             ${REPO}/assets/packaging/get-latest-zebra.cmd"
elif [ "${GOOS}_${GOARCH}_${CGO_ENABLED}" = "linux_arm_0" ]; then
  SOURCES="${SOURCES} \
             ${REPO}/assets/packaging/zebra.sh \
             ${REPO}/assets/packaging/get-latest-zebra.sh"
  GOARM=${GORAM:-5}
elif [ "${GOOS}_${GOARCH}_${CGO_ENABLED}" = "linux_arm_1" ]; then
  SOURCES="${SOURCES} \
             ${REPO}/assets/packaging/zebra.sh \
             ${REPO}/assets/packaging/get-latest-zebra.sh"
  CC=${ARM_CC:-arm-linux-gnueabihf-gcc}
  GOARM=${GORAM:-5}
elif [ "${GOOS}" = "darwin" ]; then
  SOURCES="${SOURCES} \
             ${REPO}/assets/packaging/zebra-macos.command \
             ${REPO}/assets/packaging/get-latest-zebra.sh"
else
  SOURCES="${SOURCES} \
             ${REPO}/assets/packaging/get-latest-zebra.sh \
             ${REPO}/assets/packaging/zebra-gtk.desktop \
             ${REPO}/assets/packaging/zebra-gtk.png \
             ${REPO}/assets/packaging/zebra-gtk.py \
             ${REPO}/assets/packaging/zebra.sh"
fi

build() {
  mkdir -p "${OBJECTDIR}"
  env GOOS="${GOOS}" \
    GOARCH="${GOARCH}" \
    GOARM="${GOARM}" \
    CGO_ENABLED="${CGO_ENABLED}" \
    CC="${CC}" \
    go build -v -ldflags="${LDFLAGS}" -o "${OBJECTDIR}"/"${ZEBRA_EXE}" .
}

dist() {
  mkdir -p "${DISTDIR}" "${STAGEDIR}" "${ZEBRA_STAGEDIR}"
  cp ${OBJECTS} ${SOURCES} ${ZEBRA_STAGEDIR}

  pushd "${STAGEDIR}"
  ${ZEBRA_DISTCMD} ${ZEBRA_DIST} *
  popd
}

check() {
  ZEBRA_WAIT_SECONDS=0 ${ZEBRA_STAGEDIR}/${ZEBRA_EXE}
}

clean() {
  rm -rf "${BUILDROOT}"
}

case $1 in
  build)
    build
    ;;
  dist)
    dist
    ;;
  check)
    check
    ;;
  clean)
    clean
    ;;
  *)
    build
    dist
    ;;
esac
