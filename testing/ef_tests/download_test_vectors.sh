#!/usr/bin/env bash
set -Eeuo pipefail

TESTS=("general" "minimal" "mainnet")

version=${1}
if [[ "$version" == "nightly" || "$version" =~ ^nightly-[0-9]+$ ]]; then
	if [[ -z "${GITHUB_TOKEN:-}" ]]; then
		echo "Error GITHUB_TOKEN is not set"
		exit 1
	fi

	for cmd in jq; do
		if ! command -v "${cmd}" >/dev/null 2>&1; then
			echo "Error ${cmd} is not installed"
			exit 1
		fi
	done

	repo="ethereum/consensus-specs"
	api="https://api.github.com"
	auth_header="Authorization: token ${GITHUB_TOKEN}"

	if [[ "$version" == "nightly" ]]; then
		run_id=$(curl --fail -s -H "${auth_header}" \
			"${api}/repos/${repo}/actions/workflows/nightly-reftests.yml/runs?branch=master&status=success&per_page=1" |
			jq -r '.workflow_runs[0].id')
	else
		run_id="${version#nightly-}"
	fi

	if [[ "${run_id}" == "null" || -z "${run_id}" ]]; then
		echo "No successful nightly workflow run found"
		exit 1
	fi

	echo "Downloading nightly test vectors for run: ${run_id}"
	curl --fail -H "${auth_header}" "${api}/repos/${repo}/actions/runs/${run_id}/artifacts" |
		jq -c '.artifacts[] | {name, url: .archive_download_url}' |
		while read -r artifact; do
			name=$(echo "${artifact}" | jq -r .name)
			url=$(echo "${artifact}" | jq -r .url)

			if [[ "$name" == "consensustestgen.log" ]]; then
				continue
			fi

			echo "Downloading artifact: ${name}"
			curl --progress-bar --location --show-error --retry 3 --retry-all-errors --fail \
				-H "${auth_header}" -H "Accept: application/vnd.github+json" \
				--output "${name}" "${url}" || {
				echo "Failed to download ${name}"
				exit 1
			}
		done
else
	for test in "${TESTS[@]}"; do
		if [[ ! -e "${test}.tar.gz" ]]; then
			echo "Downloading: ${version}/${test}.tar.gz"
			curl --progress-bar --location --remote-name --show-error --retry 3 --retry-all-errors --fail \
				"https://github.com/ethereum/consensus-specs/releases/download/${version}/${test}.tar.gz" \
				|| {
					echo "Curl failed. Aborting"
					rm -f "${test}.tar.gz"
					exit 1
				}
		fi
	done
fi

# Download FCR (Fast Confirmation Rule) test vectors.
# These are hosted separately until merged into consensus-spec-tests releases.
# Source: https://github.com/ethereum/consensus-specs/pull/4747
# Spec commit: 8241c1d7
FCR_TESTS_URL="${FCR_TESTS_URL:-https://github.com/user-attachments/files/26166458/fcr-fulu-8241c1d7.tar.gz}"
if [[ -n "${FCR_TESTS_URL}" ]]; then
	fcr_tarball="fcr-fulu-8241c1d7.tar.gz"
	echo "Downloading FCR test vectors"
	curl --progress-bar --location --show-error --retry 3 --retry-all-errors --fail \
		--output "${fcr_tarball}" "${FCR_TESTS_URL}" \
		|| {
			echo "FCR test vectors download failed (non-fatal)"
			rm -f "${fcr_tarball}"
		}
	if [[ -f "${fcr_tarball}" ]]; then
		tar -xzf "${fcr_tarball}"
		rm -f "${fcr_tarball}"
	fi
fi
