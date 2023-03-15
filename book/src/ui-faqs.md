# Frequently Asked Questions

## 1. Are there any requirements to run Siren?
Yes, Siren requires Lighthouse v3.5.1 or higher to function properly. These releases can be found on the [releases](https://github.com/sigp/lighthouse/releases) page of the Lighthouse repository.

## 2. Where can I find my API token?
The required Api token may be found in the default data directory of the validator client. For more information please refer to the lighthouse ui configuration [`api token section`](./ui-configuration.md#api-token).

## 3. How do I fix the Node Network Errors?
If you recieve a red notification with a BEACON or VALIDATOR NODE NETWORK ERROR you can refer to the lighthouse ui configuration and [`connecting to clients section`](./ui-configuration.md#connecting-to-the-clients).

## 4. How do I change my Beacon or Validator address after logging in?
Once you have successfully arrived to the main dashboard, use the sidebar to access the settings view. In the top right hand corner there is a `Configurtion` action button that will redirect you back to the configuration screen where you can make appropriate changes.

## 5. Why doesn't my validator balance graph show any data?
If your graph is not showing data, it usually means your validator node is still caching data. The application must wait at least 3 epochs before it can render any graphical visualizations. This could take up to 20min.
