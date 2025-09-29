"""
Summarise pull requests between two Lighthouse releases.

Usage:
  export GITHUB_TOKEN=your_token
  python -m pip install requests==2.32.4
  python print_release_diffs.py --base v7.0.1 --head release-v7.1.0

Shows commit SHA, PR number, 'backwards-incompat' label status, and PR title.
"""

import requests
import re
import argparse
import os

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
if not GITHUB_TOKEN:
    raise SystemExit("Error: Please set the GITHUB_TOKEN environment variable.")

parser = argparse.ArgumentParser(description="Summarise PRs between two Lighthouse versions.")
parser.add_argument("--base", required=True, help="Base tag or branch (older release)")
parser.add_argument("--head", required=True, help="Head tag or branch (newer release)")
args = parser.parse_args()

BASE = args.base
HEAD = args.head
OWNER = 'sigp'
REPO = 'lighthouse'

HEADERS = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github+json'
}

def get_commits_between(base, head):
    url = f'https://api.github.com/repos/{OWNER}/{REPO}/compare/{base}...{head}'
    response = requests.get(url, headers=HEADERS)
    response.raise_for_status()
    return response.json()['commits']

def has_backwards_incompat_label(pr_number):
    url = f'https://api.github.com/repos/{OWNER}/{REPO}/issues/{pr_number}'
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch PR #{pr_number}")
    labels = response.json().get('labels', [])
    return any(label['name'] == 'backwards-incompat' for label in labels)

def main():
    commits = get_commits_between(BASE, HEAD)
    print(" #   Commit SHA    PR Number    Has backwards-incompat Label    PR Title")
    print("---  ------------  -----------  ------------------------------  --------------------------------------------")

    for i, commit in enumerate(commits, 1):
        sha = commit['sha'][:12]
        message = commit['commit']['message']
        pr_match = re.search(r"\(#(\d+)\)", message)

        if not pr_match:
            print(f"{i:<3}  {sha}  {'-':<11}  {'-':<30}  [NO PR MATCH]: {message.splitlines()[0]}")
            continue

        pr_number = int(pr_match.group(1))
        try:
            has_label = has_backwards_incompat_label(pr_number)
            print(f"{i:<3}  {sha}  {pr_number:<11}  {str(has_label):<30}  {message.splitlines()[0]}")
        except Exception as e:
            print(f"{i:<3}  {sha}  {pr_number:<11}  {'ERROR':<30}  [ERROR FETCHING PR]: {e}")

if __name__ == '__main__':
    main()
