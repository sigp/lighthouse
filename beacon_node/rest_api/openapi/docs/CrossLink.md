# CrossLink

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**shard** | **u64** | The shard number. | [optional] [default to None]
**start_epoch** | **u64** | The first epoch which the crosslinking data references. | [optional] [default to None]
**end_epoch** | **u64** | The 'end' epoch referred to by the crosslinking data; no data in this Crosslink should refer to the `end_epoch` since it is not included in the crosslinking data interval. | [optional] [default to None]
**parent_root** | [***swagger::ByteArray**](ByteArray.md) | Root of the previous crosslink. | [optional] [default to None]
**data_root** | [***swagger::ByteArray**](ByteArray.md) | Root of the crosslinked shard data since the previous crosslink. | [optional] [default to None]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


