# BeaconBlockBody

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**randao_reveal** | [***swagger::ByteArray**](ByteArray.md) | The RanDAO reveal value provided by the validator. | [optional] [default to None]
**eth1_data** | [***models::Eth1Data**](Eth1Data.md) |  | [optional] [default to None]
**graffiti** | [***swagger::ByteArray**](ByteArray.md) |  | [optional] [default to None]
**proposer_slashings** | [**Vec<models::ProposerSlashings>**](ProposerSlashings.md) |  | [optional] [default to None]
**attester_slashings** | [**Vec<models::AttesterSlashings>**](AttesterSlashings.md) |  | [optional] [default to None]
**attestations** | [**Vec<models::Attestation>**](Attestation.md) |  | [optional] [default to None]
**deposits** | [**Vec<models::Deposit>**](Deposit.md) |  | [optional] [default to None]
**voluntary_exits** | [**Vec<models::VoluntaryExit>**](VoluntaryExit.md) |  | [optional] [default to None]
**transfers** | [**Vec<models::Transfer>**](Transfer.md) |  | [optional] [default to None]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


