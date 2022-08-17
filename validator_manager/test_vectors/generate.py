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


def setup():
    if os.path.exists(tmp_dir):
        cleanup()

    os.mkdir(tmp_dir)
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


def sdc_generate(network, first_index, count):
    process = Popen([
        '/bin/sh',
        'deposit.sh',
        'existing-mnemonic',
    ], stdout=PIPE, stdin=PIPE, stderr=STDOUT, cwd=sdc_git_dir, text=True)
    process.stdin.write('3\n') # Select "3. English" as the mnemonic language.
    process.stdin.write(TEST_MNEMONIC + '\n')
    process.stdin.write(str(first_index) + '\n')
    process.stdin.write(str(first_index) + '\n')
    process.stdin.write(str(count) + '\n')
    process.stdin.write(network + '\n')
    process.stdin.write('junk_password\n')
    process.stdin.write('junk_password\n')
    process.wait()
    # process.wait()
    # Select "3. English" as the mnemonic language.
    # p.communicate(input='3'.encode('utf-8'))
    # Input the mnemonic.
    # p.communicate(input=TEST_MNEMONIC.encode('utf-8'))



def test(network):
    setup()
    sdc_generate(network, 0, 2)
    # cleanup()


test("mainnet")
