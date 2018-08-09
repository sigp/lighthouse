# simpleserialize (ssz)

This is a **work-in-progress** crate designed to perform the "simpleserialize"
serialization described by Vitalik Buterin. The method is tentatively intended
for use in the Ethereum Beacon Chain.

There are two primary sources for this spec, and they are presently
conflicting:

 - The ethereum/beacon_chain reference implementation [simpleserialize.py](https://github.com/ethereum/beacon_chain/blob/master/beacon_chain/utils/simpleserialize.py) file.
 - The [py_ssz module](https://github.com/ethereum/research/tree/master/py_ssz)
   in ethereum/research.

This implementation is presently a placeholder until the final spec is decided.
Do not rely upon it for reference.

## TODO

 - Wait for spec to finalize.
 - Implement encoding for all useful types.
 - Implement decoding.
