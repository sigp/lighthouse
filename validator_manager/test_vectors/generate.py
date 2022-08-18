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

def sdc_generate(network, first_index, count):
    test_name = "{}_first_{}_count_{}".format(network, first_index, count)
    output_dir = os.path.join(vectors_dir, test_name)
    os.mkdir(output_dir)

    print("Running " + test_name)
    process = Popen([
        '/bin/sh',
        'deposit.sh',
        '--language', 'english',
        '--non_interactive',
        'existing-mnemonic',
        '--validator_start_index', str(first_index),
        '--num_validators', str(count),
        '--mnemonic', TEST_MNEMONIC,
        '--chain', 'mainnet',
        '--keystore_password', 'MyPassword',
        '--folder', os.path.abspath(output_dir),
    ], cwd=sdc_git_dir, text=True, stdin = PIPE)
    process.wait()



def test_network(network):
    sdc_generate(network, first_index=0, count=1)
    sdc_generate(network, first_index=0, count=2)
    sdc_generate(network, first_index=0, count=3)
    sdc_generate(network, first_index=12, count=1)
    sdc_generate(network, first_index=99, count=2)
    sdc_generate(network, first_index=1024, count=3)


setup()
test_network("mainnet")
test_network("prater")
cleanup()
