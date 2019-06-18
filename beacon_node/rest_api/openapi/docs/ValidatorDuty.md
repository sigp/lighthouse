# ValidatorDuty

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**validator_pubkey** | [***swagger::ByteArray**](ByteArray.md) | The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._ | [optional] [default to None]
**attestation_slot** | **u64** | The slot at which the validator must attest. | [optional] [default to None]
**attestation_shard** | **u64** | The shard in which the validator must attest. | [optional] [default to None]
**block_proposal_slot** | **u64** | The slot in which a validator must propose a block, or `null` if block production is not required. | [optional] [default to None]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


