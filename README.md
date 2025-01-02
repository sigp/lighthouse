# Algen L1: EVM compatible consensus layer

An open-source Ethereum consensus client, written in Rust.

![Banner](https://pub-4e071c7391f448248e0beb38499ef45f.r2.dev/algen/ALG.png)

## Overview

ALG Layer1: Governance and Security
ALG's L1 and L2 adopt a dual-layer node design, divided into the "governors" or "ultimate 
validators" of the L1 and the "executing validators" of the L2. ALG L1 will start from the 
compatibility of new standards such as AA and create an exemplary value layer for the hyper 
application blockchain, achieving a harmonious equilibrium between economy, security, and 
efficiency. Based on the strong interoperability of ALG L0 & L1, combined with the off-chain 
data availability of L2, it provides users with safe and convenient services. L1 is mainly 
responsible for DPoS/governance/security, and L2 is mainly responsible for verification/
execution/service/performance/interaction.
ALG's public blockchain L1 adopts the Delegated Proof of Stake (DPoS) consensus mechanism, 
high-frequency trading algorithms, and technology. This deployment fits the high-frequency and 
efficient decentralized financial attributes of Web3.0 applications. DPoS, proposed by Dan 
Larimer and implemented in the BitShares project for the first time, is a consensus mechanism 
that uses delegated stakeholders to validate blocks and solve consensus problems. ALG 
improves the algorithm based on the Byzantine fault tolerance mechanism, using a new 
permutation algorithm based on chaos factors and Verifiable Random Functions (VRF) to reduce 
the risk of malicious node attacks that have plagued DeFi infrastructure for the long term.
In ALG, the Proof of Stake mechanism is an important part of the consensus mechanism and 
incentives. Users (nodes) become potential "governors" by staking their ALG tokens through 
smart contracts. The probability of a user becoming an actual governor depends on the 
proportion of their "stake" to the total stake held in the smart contract. At the same time, the 
ALG tokens staked by the governors should also be adjusted with the fluctuation of the total 
asset value staked on the blockchain, achieving over-collateralization and laying a good trust 
foundation for the operation of the entire network.
ALG governors implement a dynamic update mechanism, with 21 governors elected in each 
round. During elections, these governors process information on the main network according to 
the Istanbul Byzantine fault tolerance algorithm. The ranking of these 21 nodes is affected by 
continuous permutations. Any node participating in malicious behavior will have its tokens 
deducted. Governors will be rewarded in three ways:

- Validators receive staking rewards allocated by the dynamic equilibrium mechanism from token 
inflation.
- Validators charge partial governance and service fees.
- Validators benefit from the long-term value growth of ALG tokens.

## Architecture

<img width="915" alt="image" src="https://github.com/user-attachments/assets/2e7b516d-8301-45fc-b43d-1c9c0d706527" />

