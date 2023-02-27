# Usage

# Dashboard

Siren's dashboard view provides a summary of all performance and key validator metrics. Sync statuses, uptimes, accumulated rewards, hardware and network metrics are all consolidated on the dashboard for evaluation.

![](imgs/ui-dashboard.png)

## Account Earnings

The account earnings component accumulates reward data from all registered validators providing a summation of total rewards earned while staking. Given current conversion rates, this component also converts your balance into your selected fiat currency.

Below in the earning section, you can also view your total earnings or click the adjacent buttons to view your estimated earnings given a specific timeframe based on current device and network conditions.

![](imgs/ui-account-earnings.png)

## Validator Table

The validator table component is a list of all registered validators, which includes data such as name, index, total balance, earned rewards and current status. Each validator row also contains a link to a detailed data modal and additional data provided by [Beaconcha.in](https://beaconcha.in).

![](imgs/ui-validator-table.png)

## Validator Balance Chart

The validator balance component is a graphical representation of each validator balance over the latest 10 epochs. Take note that only active validators are rendered in the chart visualization.

![](imgs/ui-validator-balance1.png)

By clicking on the chart component you can filter selected validators in the render. This call allow for greater resolution in the rendered visualization.

<img src="imgs/ui-balance-modal.png" width="48%" style="display: inline; float: left; margin-right: 4%"/>

<img src="imgs/ui-validator-balance2.png" width="48%"/>


## Hardware Usage and Device Diagnostics

The hardware usage component gathers information about the device the Beacon Node is currently running. It displays the Disk usage, CPU metrics and memory usage of the Beacon Node device. The device diagnostics component provides the sync status of the execution client and beacon node.

<img height="350" src="imgs/ui-hardware.png" style="display: inline; float: left; margin-right: 25px"/>

<img height="350" src="imgs/ui-device.png"/>


# Validator Management

Siren's validator management view provides a detailed overview of all validators with options to deposit to and/or add new validators. Each validator table row displays the validator name, index, balance, rewards, status and all available actions per validator.

![](imgs/ui-validator-management.png)

## Validator Modal

Clicking the validator icon activates a detailed validator modal component. This component also allows users to trigger validator actions and as well to view and update validator graffiti. Each modal contains the validator total income with hourly, daily and weekly earnings estimates.

<img height="450" src="imgs/ui-validator-modal.png"/>

# Settings

Siren's settings view provides access to the application theme, version, name, device name and important external links. From the settings page users can also access the configuration screen to adjust any beacon or validator node parameters.

![](imgs/ui-settings.png)
