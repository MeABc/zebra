#!/bin/bash -xe

export GITHUB_USER=${GITHUB_USER:-MeABc}
export GITHUB_EMAIL=${GITHUB_EMAIL:-MeABc@noreply.github.com}
export GITHUB_REPO=${GITHUB_REPO:-zebra}
export GITHUB_CI_REPO=${GITHUB_CI_REPO:-zebra-ci}
export GITHUB_COMMIT_ID=${TRAVIS_COMMIT:-${COMMIT_ID:-master}}
# export SOURCEFORGE_USER=${SOURCEFORGE_USER:-${GITHUB_USER}}
# export SOURCEFORGE_REPO=${SOURCEFORGE_REPO:-${GITHUB_REPO}}
WORKING_DIR=$(pwd)/${GITHUB_REPO}.$(date "+%y%m%d").${RANDOM:-$$}
export WORKING_DIR
export GOROOT_BOOTSTRAP=${WORKING_DIR}/goroot_bootstrap
export GOROOT=${WORKING_DIR}/go
export GOPATH=${WORKING_DIR}/gopath
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
export GOTIP_FOLLOW=${GOTIP_FOLLOW:-true}

if [ ${#GITHUB_TOKEN} -eq 0 ]; then
  echo "WARNING: \$GITHUB_TOKEN is not set!"
fi

# if [ ${#SOURCEFORGE_PASSWORD} -eq 0 ]; then
# 	echo "WARNING: \$SOURCEFORGE_PASSWORD is not set!"
# fi

for CMD in curl awk git tar bzip2 xz 7za gcc make sha1sum timeout; do
  if ! type -p ${CMD}; then
    echo -e "\\e[1;31mtool ${CMD} is not installed, abort.\\e[0m"
    exit 1
  fi
done

mkdir -p "${WORKING_DIR}"

function rename() {
  for FILENAME in "${@:2}"; do
    local NEWNAME
    NEWNAME=$(echo "${FILENAME}" | sed -r "$1")
    if [ "${NEWNAME}" != "${FILENAME}" ]; then
      mv -f "${FILENAME}" "${NEWNAME}"
    fi
  done
}

function init_github() {
  pushd "${WORKING_DIR}"

  git config --global user.name "${GITHUB_USER}"
  git config --global user.email "${GITHUB_EMAIL}"

  if ! grep -q 'machine github.com' ~/.netrc; then
    if [ ${#GITHUB_TOKEN} -gt 0 ]; then
      (
        set +x
        echo "machine github.com login $GITHUB_USER password $GITHUB_TOKEN" >>~/.netrc
      )
    fi
  fi

  popd
}

function build_go() {
  pushd "${WORKING_DIR}"

  curl -k https://storage.googleapis.com/golang/go1.4.3.linux-amd64.tar.gz | tar xz
  mv go goroot_bootstrap

  git clone --branch master https://github.com/MeABc/go
  cd go/src
  # if [ "${GOTIP_FOLLOW}" = "true" ]; then
  # 	git remote add -f upstream https://github.com/golang/go
  # 	git rebase upstream/master
  # fi
  bash ./make.bash
  # grep -q 'machine github.com' ~/.netrc && git push -f origin master

  set +ex
  echo '================================================================================'
  cat /etc/issue
  uname -a
  lscpu
  echo
  go version
  go env
  echo
  # env | grep -v GITHUB_TOKEN | grep -v SOURCEFORGE_PASSWORD
  env | grep -v GITHUB_TOKEN
  echo '================================================================================'
  set -ex

  popd
}

function build_glog() {
  pushd "${WORKING_DIR}"

  git clone https://github.com/MeABc/glog "${GOPATH}"/src/github.com/MeABc/glog
  cd "${GOPATH}"/src/github.com/MeABc/glog
  # git remote add -f upstream https://github.com/golang/glog
  # git rebase upstream/master
  go build -v
  # grep -q 'machine github.com' ~/.netrc && git push -f origin master

  popd
}

function build_http2() {
  pushd "${WORKING_DIR}"

  git clone https://github.com/MeABc/net "${GOPATH}"/src/github.com/MeABc/net
  cd "${GOPATH}"/src/github.com/MeABc/net/http2
  # git remote add -f upstream https://github.com/golang/net
  # git rebase upstream/master
  go get -x github.com/MeABc/net/http2
  # grep -q 'machine github.com' ~/.netrc && git push -f origin master

  popd
}

function build_bogo() {
  pushd "${WORKING_DIR}"

  git clone https://github.com/MeABc/bogo "${GOPATH}"/src/github.com/MeABc/bogo
  cd "${GOPATH}"/src/github.com/MeABc/bogo
  go get -x github.com/MeABc/bogo

  popd
}

function build_quicgo() {
  pushd "${WORKING_DIR}"

  git clone https://github.com/MeABc/quic-go "${GOPATH}"/src/github.com/MeABc/quic-go
  cd "${GOPATH}"/src/github.com/MeABc/quic-go
  # git remote add -f upstream https://github.com/lucas-clemente/quic-go
  # git rebase upstream/master
  go get -v github.com/MeABc/quic-go/h2quic
  # grep -q 'machine github.com' ~/.netrc && git push -f origin master

  popd
}

function build_repo() {
  pushd "${WORKING_DIR}"

  git clone https://github.com/"${GITHUB_USER}"/"${GITHUB_REPO}" "${GITHUB_REPO}"
  cd "${GITHUB_REPO}"

  if [ "${TRAVIS_PULL_REQUEST:-false}" == "false" ]; then
    git checkout -f "${GITHUB_COMMIT_ID}"
  else
    git fetch origin pull/"${TRAVIS_PULL_REQUEST}"/head:pr
    git checkout -f pr
  fi

  RELEASE=$(git rev-list --count HEAD)
  export RELEASE
  RELEASE_DESCRIPTION=$(git log -1 --oneline --format="r${RELEASE}: [\`%h\`](https://github.com/${GITHUB_USER}/${GITHUB_REPO}/commit/%h) %s")
  export RELEASE_DESCRIPTION
  if [ -n "${TRAVIS_BUILD_ID}" ]; then
    RELEASE_DESCRIPTION=$(echo "${RELEASE_DESCRIPTION}" | sed -E "s#^(r[0-9]+)#[\\1](https://travis-ci.org/${GITHUB_USER}/${GITHUB_REPO}/builds/${TRAVIS_BUILD_ID})#g")
    export RELEASE_DESCRIPTION
  fi

  if grep -lr "$(printf '\r\n')" -- * | grep '.go$'; then
    echo -e "\\e[1;31mPlease run dos2unix for go source files\\e[0m"
    exit 1
  fi

  if [ "$(gofmt -l . | tee /dev/tty)" != "" ]; then
    echo -e "\\e[1;31mPlease run 'gofmt -s -w .' for go source files\\e[0m"
    exit 1
  fi

  awk 'match($1, /"((github\.com|golang\.org|gopkg\.in)\/.+)"/) {if (!seen[$1]++) {gsub("\"", "", $1); print $1}}' $(find . -name "*.go") | xargs -n1 -i go get -u -v {}

  go test -v ./httpproxy/helpers

  # if curl -m 3 https://pki.google.com >/dev/null ; then
  # 	GoogleG2PKP=$(curl -s https://pki.google.com/GIAG2.crt | openssl x509 -inform der -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64)
  # 	sed -i -r "s/\"GoogleG2PKP\": \".+\"/\"GoogleG2PKP\": \"$GoogleG2PKP\"/g" httpproxy/filters/gae/gae.json
  # 	if git status -s | grep -q 'gae.json' ; then
  # 		git diff
  # 		git add httpproxy/filters/gae/gae.json
  # 		git commit -m "update GoogleG2PKP to $GoogleG2PKP"
  # 		grep -q 'machine github.com' ~/.netrc && git push -f origin master
  # 	fi
  # fi

  pushd ./assets/taskbar
  chmod +x ./make.bash
  env GOARCH=amd64 ./make.bash
  env GOARCH=386 ./make.bash
  popd

  chmod +x ./make.bash

  cat <<EOF |
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 ./make.bash
GOOS=freebsd GOARCH=386 CGO_ENABLED=0 ./make.bash
GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 ./make.bash
GOOS=freebsd GOARCH=arm CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=386 CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=arm CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=arm CGO_ENABLED=1 ./make.bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=mips CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=mips64 CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=mips64le CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=mipsle CGO_ENABLED=0 ./make.bash
GOOS=windows GOARCH=386 CGO_ENABLED=0 ./make.bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 ./make.bash
EOF
  xargs --max-procs=5 -n1 -i bash -c {}

  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 ./make.bash check

  mkdir -p "${WORKING_DIR}"/r"${RELEASE}"
  cp -r build/*/dist/* "${WORKING_DIR}"/r"${RELEASE}"
  # test $(ls -1 ${WORKING_DIR}/r${RELEASE} | wc -l) -eq 15

  git archive --format=tar --prefix="zebra-r${RELEASE}/" HEAD | xz >"${WORKING_DIR}/r${RELEASE}/source.tar.xz"

  # export GAE_RELEASE=$(git rev-list --count origin/server.gae)
  # git archive --format=zip --prefix="zebra-r${GAE_RELEASE}/" origin/server.gae > "${WORKING_DIR}/r${RELEASE}/zebra-gae-r${GAE_RELEASE}.zip"

  cd "${WORKING_DIR}"/r"${RELEASE}"
  rename 's/_darwin_(amd64|386)/_macos_\1/' -- *
  rename 's/_darwin_(arm64|arm)/_ios_\1/' -- *
  # rename 's/_linux_arm-/_linux_armv6l-/' *
  # rename 's/_linux_arm64/_linux_aarch64/' *

  mkdir -p Zebra.app/Contents/{MacOS,Resources}
  tar xvpf zebra_macos_amd64-r"${RELEASE}".tar.bz2 -C Zebra.app/Contents/MacOS/
  cp "${WORKING_DIR}"/"${GITHUB_REPO}"/assets/packaging/zebra-macos.icns Zebra.app/Contents/Resources/
  cat <<EOF >Zebra.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>CFBundleExecutable</key>
        <string>zebra-macos</string>
        <key>CFBundleGetInfoString</key>
        <string>Zebra For macOS</string>
        <key>CFBundleIconFile</key>
        <string>zebra-macos</string>
        <key>CFBundleName</key>
        <string>Zebra</string>
        <key>CFBundlePackageType</key>
        <string>APPL</string>
</dict>
</plist>
EOF
  cat <<EOF >Zebra.app/Contents/MacOS/zebra-macos
#!$(head -1 Zebra.app/Contents/MacOS/zebra-macos.command | tr -d '()' | awk '{print $1}')
import os
__file__ = os.path.join(os.path.dirname(__file__), 'zebra-macos.command')
text = open(__file__, 'rb').read()
code = compile(text[text.index('\n'):], __file__, 'exec')
exec code
EOF
  chmod +x Zebra.app/Contents/MacOS/zebra-macos
  BZIP=-9 tar cvjpf zebra_macos_app-r"${RELEASE}".tar.bz2 Zebra.app
  rm -rf Zebra.app

  for FILE in zebra_windows_*.7z; do
    cat "${WORKING_DIR}"/"${GITHUB_REPO}"/assets/packaging/7zCon.sfx "${FILE}" >"${FILE}".exe
    /bin/mv "${FILE}".exe "${FILE}"
  done

  ls -lht

  popd
}

function build_server_gae() {
  pushd "${WORKING_DIR}"/"${GITHUB_REPO}"

  git checkout -f server.gae
  git fetch origin server.gae
  git reset --hard origin/server.gae
  git clean -dfx .

  for FILE in python27.exe python27.dll python27.zip; do
    curl -LOJ https://raw.githubusercontent.com/MeABc/pybuild/master/${FILE}
  done

  echo -e '@echo off\n"%~dp0python27.exe" uploader.py || pause' >uploader.bat

  GAE_RELEASE=$(git rev-list --count HEAD)
  export GAE_RELEASE
  sed -i "s/r9999/r${GAE_RELEASE}/" gae/gae.go
  tar cvJpf "${WORKING_DIR}"/r"${RELEASE}"/zebra-gae-r"${GAE_RELEASE}".tar.xz -- *

  popd
}

function build_server_vps() {
  pushd "${WORKING_DIR}"/"${GITHUB_REPO}"

  git checkout -f server.vps
  git fetch origin server.vps
  git reset --hard origin/server.vps
  git clean -dfx .

  git clone --branch master https://github.com/MeABc/zebra "${GOPATH}"/src/github.com/MeABc/zebra
  awk 'match($1, /"((github\.com|golang\.org|gopkg\.in)\/.+)"/) {if (!seen[$1]++) {gsub("\"", "", $1); print $1}}' $(find . -name "*.go") | xargs -n1 -i go get -u -v {}

  cat <<EOF |
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=386 CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=arm CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 ./make.bash
GOOS=linux GOARCH=mipsle CGO_ENABLED=0 ./make.bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 ./make.bash
GOOS=windows GOARCH=386 CGO_ENABLED=0 ./make.bash
EOF
    xargs --max-procs=5 -n1 -i bash -c {}

  local files
  files=$(find ./build -type f -name "*.gz" -or -name "*.bz2" -or -name "*.xz" -or -name "*.7z")
  cp "${files}" "${WORKING_DIR}"/r"${RELEASE}"

  cd "${WORKING_DIR}"/r"${RELEASE}"
  rename 's/_darwin_(amd64|386)/_macos_\1/' -- *

  popd
}

function release_github() {
  pushd "${WORKING_DIR}"

  if [ ${#GITHUB_TOKEN} -eq 0 ]; then
    echo -e "\\e[1;31m\$GITHUB_TOKEN is not set, abort\\e[0m"
    exit 1
  fi

  git clone --branch "master" https://github.com/"${GITHUB_USER}"/"${GITHUB_CI_REPO}" "${GITHUB_CI_REPO}"
  cd "${GITHUB_CI_REPO}"

  git commit --allow-empty -m "release"
  git tag -d r"${RELEASE}" || true
  git tag r"${RELEASE}"
  git push -f origin r"${RELEASE}"

  cd "${WORKING_DIR}"
  local GITHUB_RELEASE_URL=https://github.com/aktau/github-release/releases/download/v0.6.2/linux-amd64-github-release.tar.bz2
  local GITHUB_RELEASE_BIN
  GITHUB_RELEASE_BIN=$(pwd)/$(curl -L ${GITHUB_RELEASE_URL} | tar xjpv | head -1)

  cd "${WORKING_DIR}"/r"${RELEASE}"/

  for i in $(seq 5); do
    if ! ${GITHUB_RELEASE_BIN} release --user "${GITHUB_USER}" --repo "${GITHUB_CI_REPO}" --tag r"${RELEASE}" --name "${GITHUB_REPO} r${RELEASE}" --description "${RELEASE_DESCRIPTION}"; then
      sleep 3
      ${GITHUB_RELEASE_BIN} delete --user "${GITHUB_USER}" --repo "${GITHUB_CI_REPO}" --tag r"${RELEASE}" >/dev/null 2>&1 || true
      sleep 3
      continue
    fi

    local allok="true"
    for FILE in *; do
      if ! timeout -k60 60 "${GITHUB_RELEASE_BIN}" upload --user "${GITHUB_USER}" --repo "${GITHUB_CI_REPO}" --tag r"${RELEASE}" --name "${FILE}" --file "${FILE}"; then
        allok="false"
        break
      fi
    done
    if [ "${allok}" == "true" ]; then
      break
    fi
  done

  local files
  files=$(ls "${WORKING_DIR}"/r"${RELEASE}"/ | wc -l)
  local uploads
  uploads=$(${GITHUB_RELEASE_BIN} info --user "${GITHUB_USER}" --repo "${GITHUB_CI_REPO}" --tag r"${RELEASE}" | grep -- '- artifact: ' | wc -l)
  test "${files}" -eq "${uploads}"

  popd
}

function release_sourceforge() {
  pushd "${WORKING_DIR}"/

  if [ ${#SOURCEFORGE_PASSWORD} -eq 0 ]; then
    echo -e "\\e[1;31m\$SOURCEFORGE_PASSWORD is not set, abort\\e[0m"
    exit 1
  fi

  set +ex

  for i in $(seq 5); do
    echo Uploading r"${RELEASE}"/* to https://sourceforge.net/projects/zebra/files/r"${RELEASE}"/
    if timeout -k60 60 lftp "sftp://${SOURCEFORGE_USER}:${SOURCEFORGE_PASSWORD}@frs.sourceforge.net/home/frs/project/${SOURCEFORGE_REPO}/" -e "rm -rf r${RELEASE}; mkdir r${RELEASE}; mirror -R r${RELEASE} r${RELEASE}; bye"; then
      break
    fi
  done

  set -ex

  popd
}

function clean() {
  set +ex

  pushd "${WORKING_DIR}"/r"${RELEASE}"/
  ls -lht
  echo
  echo 'sha1sum *'
  sha1sum -- * | xargs -n1 -i echo -e "\\e[1;32m{}\\e[0m"
  popd >/dev/null
  rm -rf "${WORKING_DIR}"

  set -ex
}

init_github
build_go
build_glog
build_http2
build_bogo
build_quicgo
build_repo
if [ "x${TRAVIS_EVENT_TYPE}" == "xpush" ]; then
  # rebuild_go_with_tls13
  # build_goproxy_gae
  # build_goproxy_vps
  release_github
  # release_sourceforge
  clean
fi
