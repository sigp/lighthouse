web3.personal.importRawKey('115fe42a60e5ef45f5490e599add1f03c73aeaca129c2c41451eca6cf8ff9e04', 'password')
web3.personal.unlockAccount('0x7b8c3a386c0eea54693ffb0da17373ffc9228139', 'password', 3000)
web3.eth.sendTransaction({from: '0x7b8c3a386c0eea54693ffb0da17373ffc9228139', to: '0x0000000000000000000000000000000000000000', value: 1000})
