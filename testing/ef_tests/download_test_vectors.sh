#!/usr/bin/env bash
set -Eeuo pipefail

TESTS=("general" "minimal" "mainnet")

version=${1}
if [[ "$version" == "nightly" ]]; then
	if [[ -z "${GITHUB_TOKEN:-}" ]]; then
		echo "Error GITHUB_TOKEN is not set"
		exit 1
	fi

	for cmd in unzip jq; do
		if ! command -v "${cmd}" >/dev/null 2>&1; then
			echo "Error ${cmd} is not installed"
			exit 1
		fi
	done

	repo="ethereum/consensus-specs"
	api="https://api.github.com"
	auth_header="Authorization: token ${GITHUB_TOKEN}"

	run_id=$(curl -s -H "${auth_header}" \
		"${api}/repos/${repo}/actions/workflows/generate_vectors.yml/runs?branch=dev&status=success&per_page=1" |
		jq -r '.workflow_runs[0].id')

	if [[ "${run_id}" == "null" || -z "${run_id}" ]]; then
		echo "No successful nightly workflow run found"
		exit 1
	fi

	echo "Downloading nightly test vectors for run: ${run_id}"
	curl -s -H "${auth_header}" "${api}/repos/${repo}/actions/runs/${run_id}/artifacts" |
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
				--output "${name}.zip" "${url}" || {
				echo "Failed to download ${name}"
				exit 1
			}

			unzip -qo "${name}.zip"
			rm -f "${name}.zip"
		done
else
	for test in "${TESTS[@]}"; do
		if [[ ! -e "${test}.tar.gz" ]]; then
			echo "Downloading: ${version}/${test}.tar.gz"
			curl --progress-bar --location --remote-name --show-error --retry 3 --retry-all-errors --fail \
				"https://github.com/ethereum/consensus-spec-tests/releases/download/${version}/${test}.tar.gz" \
				|| {
					echo "Curl failed. Aborting"
					rm -f "${test}.tar.gz"
					exit 1
				}
		fi
	done
fi
