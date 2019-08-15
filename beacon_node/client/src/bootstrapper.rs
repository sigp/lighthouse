use eth2_libp2p::Enr;
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

pub struct Bootstrapper {
    url: Url,
}

impl Bootstrapper {
    pub fn from_server_string(server: String) -> Result<Self, String> {
        Ok(Self {
            url: Url::parse(&server).map_err(|e| format!("Invalid bootstrap server url: {}", e))?,
        })
    }

    pub fn enr(&self) -> Result<Enr, String> {
        get_enr(self.url.clone()).map_err(|e| format!("Unable to get ENR: {:?}", e))
    }

    pub fn genesis<T: EthSpec>(&self) -> Result<(BeaconState<T>, BeaconBlock<T>), String> {
        let genesis_slot = Slot::new(0);

        let block = get_block(self.url.clone(), genesis_slot)
            .map_err(|e| format!("Unable to get genesis block: {:?}", e))?;
        let state = get_state(self.url.clone(), genesis_slot)
            .map_err(|e| format!("Unable to get genesis state: {:?}", e))?;

        Ok((state, block))
    }

    pub fn finalized<T: EthSpec>(&self) -> Result<(BeaconState<T>, BeaconBlock<T>), String> {
        let slots_per_epoch = get_slots_per_epoch(self.url.clone())
            .map_err(|e| format!("Unable to get slots per epoch: {:?}", e))?;
        let finalized_slot = get_finalized_slot(self.url.clone(), slots_per_epoch.as_u64())
            .map_err(|e| format!("Unable to get finalized slot: {:?}", e))?;

        let block = get_block(self.url.clone(), finalized_slot)
            .map_err(|e| format!("Unable to get finalized block: {:?}", e))?;
        let state = get_state(self.url.clone(), finalized_slot)
            .map_err(|e| format!("Unable to get finalized state: {:?}", e))?;

        Ok((state, block))
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

fn get_enr(mut url: Url) -> Result<Enr, Error> {
    url.path_segments_mut()
        .map(|mut url| {
            url.push("node").push("network").push("enr");
        })
        .map_err(|_| Error::UrlCannotBeBase)?;

    reqwest::get(url)?
        .error_for_status()?
        .json()
        .map_err(Into::into)
}
