import os
import shutil
import subprocess

NUM_VALIDATORS=3
TEST_MNEMONIC = "test test test test test test test test test test test waste"
WALLET_NAME="test_wallet"

tmp_dir = os.path.join(".", "tmp")
mnemonic_path = os.path.join(tmp_dir, "mnemonic.txt")
lh_dir = os.path.join(tmp_dir, "lh")
lh_json_path = os.path.join(lh_dir, "deposit-data.json")
lh_wallet_password_path = os.path.join(lh_dir, "wallet.pass")
sdc_dir = os.path.join(tmp_dir, "sdc")


def setup():
    if os.path.exists(tmp_dir):
        cleanup()
    os.mkdir(tmp_dir)
    with open(mnemonic_path, "x") as file:
        file.write(TEST_MNEMONIC)


def cleanup():
    shutil.rmtree(tmp_dir)


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
    lighthouse_generate(network)
    # cleanup()


test("mainnet")
