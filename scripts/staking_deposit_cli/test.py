import os
import sys
import shutil
import subprocess
from subprocess import Popen, PIPE, STDOUT

NUM_VALIDATORS=3
TEST_MNEMONIC = "test test test test test test test test test test test waste"
WALLET_NAME="test_wallet"

tmp_dir = os.path.join(".", "tmp")
mnemonic_path = os.path.join(tmp_dir, "mnemonic.txt")
lh_dir = os.path.join(tmp_dir, "lh")
lh_json_path = os.path.join(lh_dir, "deposit-data.json")
lh_wallet_password_path = os.path.join(lh_dir, "wallet.pass")
sdc_dir = os.path.join(tmp_dir, "sdc")
sdc_git_dir = os.path.join(sdc_dir, "staking-deposit-cli")


def setup():
    if os.path.exists(tmp_dir):
        cleanup()

    os.mkdir(tmp_dir)
    os.mkdir(lh_dir)
    os.mkdir(sdc_dir)

    setup_sdc()
    with open(mnemonic_path, "x") as file:
        file.write(TEST_MNEMONIC)


def cleanup():
    shutil.rmtree(tmp_dir)


def setup_sdc():
    result = subprocess.run([
        "git",
        "clone",
        "--single-branch",
        "https://github.com/ethereum/staking-deposit-cli.git",
        str(sdc_git_dir)
    ])
    assert(result.returncode == 0)
    result = subprocess.run([
        "pip",
        "install",
        "-r",
        "requirements.txt",
    ], cwd=sdc_git_dir)
    assert(result.returncode == 0)
    result = subprocess.run([
        "python",
        "setup.py",
        "install",
    ], cwd=sdc_git_dir)
    assert(result.returncode == 0)


def sdc_generate(network):
    p = Popen([
        '/bin/sh',
        'deposit.sh',
    ], stdin=PIPE, cwd=sdc_git_dir)
    p.communicate(input=TEST_MNEMONIC.encode('utf-8'))[0]


def lighthouse_generate(network):
    result = subprocess.run([
        "lighthouse",
        "--network",
        network,
        "account",
        "wallet",
        "recover",
        "--datadir",
        str(lh_dir),
        "--name",
        WALLET_NAME,
        "--mnemonic-path",
        str(mnemonic_path),
        "--password-file",
        str(lh_wallet_password_path)
    ])
    assert(result.returncode == 0)

    result = subprocess.run([
        "lighthouse",
        "--network",
        network,
        "account",
        "validator",
        "create",
        "--datadir",
        str(lh_dir),
        "--wallet-name",
        WALLET_NAME,
        "--wallet-password",
        str(lh_wallet_password_path),
        "--count",
        str(NUM_VALIDATORS),
        "--json-deposit-data-path",
        str(lh_json_path)
    ])
    assert(result.returncode == 0)


def test(network):
    setup()
    sdc_generate(network)
    #lighthouse_generate(network)
    # cleanup()


test("mainnet")
