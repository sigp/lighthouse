/// Map a fork name into a fork-versioned superstruct type like `BeaconBlock`.
///
/// The `$body` expression is where the magic happens. The macro allows us to achieve polymorphism
/// in the return type, which is not usually possible in Rust without trait objects.
///
/// E.g. you could call `map_fork_name!(fork, BeaconBlock, serde_json::from_str(s))` to decode
/// different `BeaconBlock` variants depending on the value of `fork`. Note how the type of the body
/// will change between `BeaconBlockBase` and `BeaconBlockAltair` depending on which branch is
/// taken, the important thing is that they are re-unified by injecting them back into the
/// `BeaconBlock` parent enum.
///
/// If you would also like to extract additional data alongside the superstruct type, use
/// the more flexible `map_fork_name_with` macro.
#[macro_export]
macro_rules! map_fork_name {
    ($fork_name:expr, $t:tt, $body:expr) => {
        $crate::map_fork_name_with!($fork_name, $t, { ($body, ()) }).0
    };
}

/// Map a fork name into a tuple of `(t, extra)` where `t` is a superstruct type.
#[macro_export]
macro_rules! map_fork_name_with {
    ($fork_name:expr, $t:tt, $body:block) => {
        match $fork_name {
            $crate::fork::ForkName::Base => {
                let (value, extra_data) = $body;
                ($t::Base(value), extra_data)
            }
            $crate::fork::ForkName::Altair => {
                let (value, extra_data) = $body;
                ($t::Altair(value), extra_data)
            }
            $crate::fork::ForkName::Bellatrix => {
                let (value, extra_data) = $body;
                ($t::Bellatrix(value), extra_data)
            }
            $crate::fork::ForkName::Capella => {
                let (value, extra_data) = $body;
                ($t::Capella(value), extra_data)
            }
            $crate::fork::ForkName::Deneb => {
                let (value, extra_data) = $body;
                ($t::Deneb(value), extra_data)
            }
            $crate::fork::ForkName::Electra => {
                let (value, extra_data) = $body;
                ($t::Electra(value), extra_data)
            }
            $crate::fork::ForkName::Fulu => {
                let (value, extra_data) = $body;
                ($t::Fulu(value), extra_data)
            }
            $crate::fork::ForkName::Gloas => {
                let (value, extra_data) = $body;
                ($t::Gloas(value), extra_data)
            }
        }
    };
}
