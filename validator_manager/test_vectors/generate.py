# This script uses the `ethereum/staking-deposit-cli` tool to generate
# deposit data files which are then used for testing by Lighthouse.
#
# To generate vectors, simply run this Python script:
#
# `python generate.py`
#
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
sdc_dir = os.path.join(tmp_dir, "sdc")
sdc_git_dir = os.path.join(sdc_dir, "staking-deposit-cli")
vectors_dir = os.path.join(".", "vectors")


def setup():
    cleanup()

    if os.path.exists(vectors_dir):
        shutil.rmtree(vectors_dir)

    os.mkdir(tmp_dir)
    os.mkdir(sdc_dir)
    os.mkdir(vectors_dir)

    setup_sdc()
    with open(mnemonic_path, "x") as file:
        file.write(TEST_MNEMONIC)


def cleanup():
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)

    # Remove all the keystores since we don't use them in testing.
    if os.path.exists(vectors_dir):
        for root, dirs, files in os.walk(vectors_dir):
            for file in files:
                if file.startswith("keystore"):
                    os.remove(os.path.join(root, file))


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


def sdc_generate(network, first_index, count, eth1_withdrawal_address=None):
    if eth1_withdrawal_address is not None:
        eth1_flags = ['--eth1_withdrawal_address', eth1_withdrawal_address]
        uses_eth1 = True
    else:
        eth1_flags = []
        uses_eth1 = False

    test_name = "{}_first_{}_count_{}_eth1_{}".format(network, first_index, count,
                                                      str(uses_eth1).lower())
    output_dir = os.path.join(vectors_dir, test_name)
    os.mkdir(output_dir)

    command = [
        '/bin/sh',
        'deposit.sh',
        '--language', 'english',
        '--non_interactive',
        'existing-mnemonic',
        '--validator_start_index', str(first_index),
        '--num_validators', str(count),
        '--mnemonic', TEST_MNEMONIC,
        '--chain', network,
        '--keystore_password', 'MyPassword',
        '--folder', os.path.abspath(output_dir),
    ] + eth1_flags

    print("Running " + test_name)
    process = Popen(command, cwd=sdc_git_dir, text=True, stdin = PIPE)
    process.wait()


def test_network(network):
    sdc_generate(network, first_index=0, count=1)
    sdc_generate(network, first_index=0, count=2)
    sdc_generate(network, first_index=12, count=1)
    sdc_generate(network, first_index=99, count=2)
    sdc_generate(network, first_index=1024, count=3)
    sdc_generate(network, first_index=0, count=2,
                 eth1_withdrawal_address="0x0f51bb10119727a7e5ea3538074fb341f56b09ad")


setup()
test_network("mainnet")
test_network("prater")
cleanup()
