# ValidatorDuty

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**validator_pubkey** | **String** | The validator's BLS public key, uniquely identifying them. _48-bytes, hex encoded with 0x prefix, case insensitive._ | [optional] 
**attestation_slot** | **i32** | The slot at which the validator must attest. | [optional] 
**attestation_shard** | **i32** | The shard in which the validator must attest. | [optional] 
**block_proposal_slot** | **i32** | The slot in which a validator must propose a block, or `null` if block production is not required. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


