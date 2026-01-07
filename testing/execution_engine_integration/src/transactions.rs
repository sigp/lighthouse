use alloy_network::TransactionBuilder;
use alloy_primitives::{Address, U256};
use alloy_rpc_types_eth::{AccessList, TransactionRequest};
use bls::{Keypair, Signature};
use deposit_contract::{BYTECODE, CONTRACT_DEPLOY_GAS, DEPOSIT_GAS, encode_eth1_tx_data};
use fixed_bytes::FixedBytesExtended;
use types::{DepositData, EthSpec, Hash256};

/// Hardcoded deposit contract address based on sender address and nonce
pub const DEPOSIT_CONTRACT_ADDRESS: &str = "64f43BEc7F86526686C931d65362bB8698872F90";

#[derive(Debug)]
pub enum Transaction {
    Transfer(Address, Address),
    TransferLegacy(Address, Address),
    TransferAccessList(Address, Address),
    DeployDepositContract(Address),
    DepositDepositContract {
        sender: Address,
        deposit_contract_address: Address,
    },
}

/// Get a list of transactions to publish to the execution layer.
pub fn transactions<E: EthSpec>(account1: Address, account2: Address) -> Vec<TransactionRequest> {
    vec![
        Transaction::Transfer(account1, account2).transaction::<E>(),
        Transaction::TransferLegacy(account1, account2).transaction::<E>(),
        Transaction::TransferAccessList(account1, account2).transaction::<E>(),
        Transaction::DeployDepositContract(account1).transaction::<E>(),
        Transaction::DepositDepositContract {
            sender: account1,
            deposit_contract_address: Address::from_slice(
                &hex::decode(DEPOSIT_CONTRACT_ADDRESS).unwrap(),
            ),
        }
        .transaction::<E>(),
    ]
}

impl Transaction {
    pub fn transaction<E: EthSpec>(&self) -> TransactionRequest {
        match &self {
            Self::TransferLegacy(from, to) => TransactionRequest::default()
                .from(*from)
                .to(*to)
                .value(U256::from(1))
                .with_gas_price(1_000_000_000u128), // 1 gwei
            Self::Transfer(from, to) => TransactionRequest::default()
                .from(*from)
                .to(*to)
                .value(U256::from(1))
                .with_max_fee_per_gas(2_000_000_000u128)
                .with_max_priority_fee_per_gas(1_000_000_000u128),
            Self::TransferAccessList(from, to) => TransactionRequest::default()
                .from(*from)
                .to(*to)
                .value(U256::from(1))
                .with_access_list(AccessList::default())
                .with_gas_price(1_000_000_000u128), // 1 gwei
            Self::DeployDepositContract(addr) => {
                let mut bytecode = String::from_utf8(BYTECODE.to_vec()).unwrap();
                bytecode.retain(|c| c.is_ascii_hexdigit());
                let bytecode = hex::decode(&bytecode[1..]).unwrap();
                let mut req = TransactionRequest::default()
                    .from(*addr)
                    .with_input(bytecode)
                    .with_gas_limit(CONTRACT_DEPLOY_GAS.try_into().unwrap())
                    .with_gas_price(1_000_000_000u128); // 1 gwei
                req.set_create();
                req
            }
            Self::DepositDepositContract {
                sender,
                deposit_contract_address,
            } => {
                let keypair = Keypair::random();

                let amount: u64 = 32_000_000_000;
                let mut deposit = DepositData {
                    pubkey: keypair.pk.into(),
                    withdrawal_credentials: Hash256::zero(),
                    amount,
                    signature: Signature::empty().into(),
                };
                deposit.signature = deposit.create_signature(&keypair.sk, &E::default_spec());
                TransactionRequest::default()
                    .from(*sender)
                    .to(*deposit_contract_address)
                    .with_input(encode_eth1_tx_data(&deposit).unwrap())
                    .with_gas_limit(DEPOSIT_GAS.try_into().unwrap())
                    .value(U256::from(amount) * U256::from(10).pow(U256::from(9)))
                    .with_gas_price(1_000_000_000u128) // 1 gwei
            }
        }
    }
}
