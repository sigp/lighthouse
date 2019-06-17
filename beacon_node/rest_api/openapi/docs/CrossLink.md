# CrossLink

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**shard** | **i32** | The shard number. | [optional] 
**start_epoch** | **i32** | The first epoch which the crosslinking data references. | [optional] 
**end_epoch** | **i32** | The 'end' epoch referred to by the crosslinking data; no data in this Crosslink should refer to the `end_epoch` since it is not included in the crosslinking data interval. | [optional] 
**parent_root** | **String** | Root of the previous crosslink. | [optional] 
**data_root** | **String** | Root of the crosslinked shard data since the previous crosslink. | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


