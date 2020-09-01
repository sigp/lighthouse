# Change the version across multiple files, prior to a release. Use `sed` to
# find/replace the exiting version with the new one.
#
# Takes two arguments:
#
# 1. Current version (e.g., `0.2.6`)
# 2. New version (e.g., `0.2.7`)
#
# ## Example:
#
# `./change_version.sh 0.2.6 0.2.7`

FROM=$1
TO=$2
VERSION_CRATE="../common/lighthouse_version/src/lib.rs"

update_cargo_toml () {
	echo $1
	sed -i -e "s/version = \"$FROM\"/version = \"$TO\"/g" $1
}

echo "Changing version from $FROM to $TO"

update_cargo_toml ../account_manager/Cargo.toml
update_cargo_toml ../beacon_node/Cargo.toml
update_cargo_toml ../boot_node/Cargo.toml
update_cargo_toml ../lcli/Cargo.toml
update_cargo_toml ../lighthouse/Cargo.toml
update_cargo_toml ../validator_client/Cargo.toml

echo $VERSION_CRATE
sed -i -e "s/$FROM/$TO/g" $VERSION_CRATE
