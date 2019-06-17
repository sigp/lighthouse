# BeaconBlock

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**slot** | **i32** | The slot to which this block corresponds. | [optional] 
**parent_root** | **String** | The signing merkle root of the parent `BeaconBlock`. | [optional] 
**state_root** | **String** | The tree hash merkle root of the `BeaconState` for the `BeaconBlock`. | [optional] 
**signature** | **String** | The BLS signature of the `BeaconBlock` made by the validator of the block. | [optional] 
**body** | [***::models::BeaconBlockBody**](BeaconBlockBody.md) |  | [optional] 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


