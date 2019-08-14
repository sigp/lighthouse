use reqwest::{Error as HttpError, Url};
use types::{BeaconBlock, BeaconState, Checkpoint, EthSpec, Slot};

#[derive(Debug)]
enum Error {
    UrlCannotBeBase,
    HttpError(HttpError),
}

impl From<HttpError> for Error {
    fn from(e: HttpError) -> Error {
        Error::HttpError(e)
    }
}

pub struct BootstrapParams<T: EthSpec> {
    pub finalized_block: BeaconBlock<T>,
    pub finalized_state: BeaconState<T>,
    pub genesis_block: BeaconBlock<T>,
    pub genesis_state: BeaconState<T>,
}

impl<T: EthSpec> BootstrapParams<T> {
    pub fn from_http_api(url: Url) -> Result<Self, String> {
        let slots_per_epoch = get_slots_per_epoch(url.clone())
            .map_err(|e| format!("Unable to get slots per epoch: {:?}", e))?;
        let genesis_slot = Slot::new(0);
        let finalized_slot = get_finalized_slot(url.clone(), slots_per_epoch.as_u64())
            .map_err(|e| format!("Unable to get finalized slot: {:?}", e))?;

        Ok(Self {
            finalized_block: get_block(url.clone(), finalized_slot)
                .map_err(|e| format!("Unable to get finalized block: {:?}", e))?,
            finalized_state: get_state(url.clone(), finalized_slot)
                .map_err(|e| format!("Unable to get finalized state: {:?}", e))?,
            genesis_block: get_block(url.clone(), genesis_slot)
                .map_err(|e| format!("Unable to get genesis block: {:?}", e))?,
            genesis_state: get_state(url.clone(), genesis_slot)
                .map_err(|e| format!("Unable to get genesis state: {:?}", e))?,
        })
    }
}

fn get_slots_per_epoch(mut url: Url) -> Result<Slot, Error> {
    url.path_segments_mut()
        .map(|mut url| {
            url.push("spec").push("slots_per_epoch");
        })
        .map_err(|_| Error::UrlCannotBeBase)?;

    reqwest::get(url)?
        .error_for_status()?
        .json()
        .map_err(Into::into)
}

fn get_finalized_slot(mut url: Url, slots_per_epoch: u64) -> Result<Slot, Error> {
    url.path_segments_mut()
        .map(|mut url| {
            url.push("beacon").push("latest_finalized_checkpoint");
        })
        .map_err(|_| Error::UrlCannotBeBase)?;

    let checkpoint: Checkpoint = reqwest::get(url)?.error_for_status()?.json()?;

    Ok(checkpoint.epoch.start_slot(slots_per_epoch))
}

fn get_state<T: EthSpec>(mut url: Url, slot: Slot) -> Result<BeaconState<T>, Error> {
    url.path_segments_mut()
        .map(|mut url| {
            url.push("beacon").push("state");
        })
        .map_err(|_| Error::UrlCannotBeBase)?;

    url.query_pairs_mut()
        .append_pair("slot", &format!("{}", slot.as_u64()));

    reqwest::get(url)?
        .error_for_status()?
        .json()
        .map_err(Into::into)
}

fn get_block<T: EthSpec>(mut url: Url, slot: Slot) -> Result<BeaconBlock<T>, Error> {
    url.path_segments_mut()
        .map(|mut url| {
            url.push("beacon").push("block");
        })
        .map_err(|_| Error::UrlCannotBeBase)?;

    url.query_pairs_mut()
        .append_pair("slot", &format!("{}", slot.as_u64()));

    reqwest::get(url)?
        .error_for_status()?
        .json()
        .map_err(Into::into)
}
