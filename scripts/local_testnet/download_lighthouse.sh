#!/usr/bin/env bash

# Download the Lighthouse version passed as the first argument.
# OS is picked automatically using uname
# Example:
# $ ./download_lighthouse.sh v5.0.0 -b lighthouse-deneb -p ~/.cargo/bin/
# ...
# $ ls ~/.cargo/bin/
# lighthouse-deneb

version=$1
shift

install_path=~/.cargo/bin/
installed_binary_name=lighthouse

# Required commands check
for cmd in curl tar uname; do
  command -v "$cmd" >/dev/null 2>&1 || { echo >&2 "This script requires $cmd but it's not installed. Aborting."; exit 1; }
done

# Check OS and set binary_name accordingly
OS=$(uname -s)
case "$OS" in
  Linux) binary_name="lighthouse-${version}-x86_64-unknown-linux-gnu.tar.gz" ;;
  Darwin) binary_name="lighthouse-${version}-x86_64-apple-darwin.tar.gz" ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Get options
while getopts "b:p:h" flag; do
  case "${flag}" in
    b) installed_binary_name=${OPTARG};;
    p)
       install_path=${OPTARG}
       # Ensure install_path ends with a slash
       install_path="${install_path%/}/";;
    h)
      echo "Download Lighthouse."
      echo
      echo "usage: $0 vX.X.X <Options> "
      echo
      echo "The first argument must be the version of Lighthouse you wish to download,"
      echo "specified as 'vX.X.X', where X.X.X is the version number."
      echo
      echo "Options:"
      echo "   -b: binary name, specify the output binary name, default: lighthouse"
      echo "   -p: install path, specify the installation path, default: ~/.cargo/bin/"
      echo "   -h: this help"
      echo "Example:"
      echo "$ ./download_lighthouse.sh v5.0.0 -b lighthouse-deneb -p ~/.cargo/bin/"
      echo "..."
      echo "$ ls ~/.cargo/bin/"
      echo "lighthouse-deneb"
      exit
      ;;
  esac
done

# Download and extract the release
echo "Downloading ${binary_name}"
if ! curl -LO "https://github.com/sigp/lighthouse/releases/download/${version}/${binary_name}"; then
  echo "Failed to download ${binary_name}"
  exit 1
fi

if ! tar -xzf "${binary_name}"; then
  echo "Failed to extract ${binary_name}"
  exit 1
fi

# Remove the tarball
echo "Removing downloaded tarball ${binary_name}"
rm "${binary_name}"

# Move the binary only if install_path is different from current directory
echo "Installing Lighthouse to ${install_path}${installed_binary_name}"
if ! mv lighthouse "${install_path}${installed_binary_name}"; then
    echo "Failed to move Lighthouse to ${install_path}${installed_binary_name}"
    exit 1
fi

echo "Lighthouse ${version} installed successfully at ${install_path}${installed_binary_name}"
