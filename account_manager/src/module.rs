pub trait CryptoModule {
    type Params;

    fn function(&self) -> String;
    fn params(&self) -> &Self::Params;
    fn message(&self) -> Vec<u8>;
}
