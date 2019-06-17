# \MinimalSetApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**node_genesis_time_get**](MinimalSetApi.md#node_genesis_time_get) | **Get** /node/genesis_time | Get the genesis_time parameter from beacon node configuration.
[**node_syncing_get**](MinimalSetApi.md#node_syncing_get) | **Get** /node/syncing | Poll to see if the the beacon node is syncing.
[**node_version_get**](MinimalSetApi.md#node_version_get) | **Get** /node/version | Get version string of the running beacon node.
[**validator_attestation_get**](MinimalSetApi.md#validator_attestation_get) | **Get** /validator/attestation | Produce an attestation, without signature.
[**validator_attestation_post**](MinimalSetApi.md#validator_attestation_post) | **Post** /validator/attestation | Publish a signed attestation.
[**validator_block_get**](MinimalSetApi.md#validator_block_get) | **Get** /validator/block | Produce a new block, without signature.
[**validator_block_post**](MinimalSetApi.md#validator_block_post) | **Post** /validator/block | Publish a signed block.
[**validator_duties_get**](MinimalSetApi.md#validator_duties_get) | **Get** /validator/duties | Get validator duties for the requested validators.



## node_genesis_time_get

> i32 node_genesis_time_get()
Get the genesis_time parameter from beacon node configuration.

Requests the genesis_time parameter from the beacon node, which should be consistent across all beacon nodes that follow the same beacon chain.

### Required Parameters

This endpoint does not need any parameter.

### Return type

**i32**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## node_syncing_get

> ::models::InlineResponse200 node_syncing_get()
Poll to see if the the beacon node is syncing.

Requests the beacon node to describe if it's currently syncing or not, and if it is, what block it is up to. This is modelled after the Eth1.0 JSON-RPC eth_syncing call..

### Required Parameters

This endpoint does not need any parameter.

### Return type

[**::models::InlineResponse200**](inline_response_200.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## node_version_get

> String node_version_get()
Get version string of the running beacon node.

Requests that the beacon node identify information about its implementation in a format similar to a  [HTTP User-Agent](https://tools.ietf.org/html/rfc7231#section-5.5.3) field.

### Required Parameters

This endpoint does not need any parameter.

### Return type

**String**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## validator_attestation_get

> ::models::IndexedAttestation validator_attestation_get(validator_pubkey, poc_bit, slot, shard)
Produce an attestation, without signature.

Requests that the beacon node produce an IndexedAttestation, with a blank signature field, which the validator will then sign.

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **validator_pubkey** | **String**| Uniquely identifying which validator this attestation is to be produced for. | 
  **poc_bit** | **i32**| The proof-of-custody bit that is to be reported by the requesting validator. This bit will be inserted into the appropriate location in the returned `IndexedAttestation`. | 
  **slot** | **i32**| The slot for which the attestation should be proposed. | 
  **shard** | **i32**| The shard number for which the attestation is to be proposed. | 

### Return type

[**::models::IndexedAttestation**](IndexedAttestation.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## validator_attestation_post

> validator_attestation_post(attestation)
Publish a signed attestation.

Instructs the beacon node to broadcast a newly signed IndexedAttestation object to the intended shard subnet. The beacon node is not required to validate the signed IndexedAttestation, and a successful response (20X) only indicates that the broadcast has been successful. The beacon node is expected to integrate the new attestation into its state, and therefore validate the attestation internally, however attestations which fail the validation are still broadcast but a different status code is returned (202)

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **attestation** | [**::models::IndexedAttestation**](.md)| An `IndexedAttestation` structure, as originally provided by the beacon node, but now with the signature field completed. | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## validator_block_get

> ::models::BeaconBlock validator_block_get(slot, randao_reveal)
Produce a new block, without signature.

Requests a beacon node to produce a valid block, which can then be signed by a validator.

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **slot** | **i32**| The slot for which the block should be proposed. | 
  **randao_reveal** | **String**| The validator's randao reveal value. | 

### Return type

[**::models::BeaconBlock**](BeaconBlock.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## validator_block_post

> validator_block_post(beacon_block)
Publish a signed block.

Instructs the beacon node to broadcast a newly signed beacon block to the beacon network, to be included in the beacon chain. The beacon node is not required to validate the signed `BeaconBlock`, and a successful response (20X) only indicates that the broadcast has been successful. The beacon node is expected to integrate the new block into its state, and therefore validate the block internally, however blocks which fail the validation are still broadcast but a different status code is returned (202)

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **beacon_block** | [**::models::BeaconBlock**](.md)| The `BeaconBlock` object, as sent from the beacon node originally, but now with the signature field completed. | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## validator_duties_get

> Vec<::models::ValidatorDuty> validator_duties_get(validator_pubkeys, optional)
Get validator duties for the requested validators.

Requests the beacon node to provide a set of _duties_, which are actions that should be performed by validators, for a particular epoch. Duties should only need to be checked once per epoch, however a chain reorganization (of > MIN_SEED_LOOKAHEAD epochs) could occur, resulting in a change of duties. For full safety, this API call should be polled at every slot to ensure that chain reorganizations are recognized, and to ensure that the beacon node is properly synchronized.

### Required Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
  **validator_pubkeys** | [**Vec<String>**](String.md)| An array of hex-encoded BLS public keys | 
 **optional** | **map[string]interface{}** | optional parameters | nil if no parameters

### Optional Parameters

Optional parameters are passed through a map[string]interface{}.

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **validator_pubkeys** | [**Vec<String>**](String.md)| An array of hex-encoded BLS public keys | 
 **epoch** | **i32**|  | 

### Return type

[**Vec<::models::ValidatorDuty>**](ValidatorDuty.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

