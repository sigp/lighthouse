mod fork_choice;
mod fork_choice_store;
mod persisted_fork_choice;

pub use fork_choice::{Error, ForkChoice};
pub use fork_choice_store::ForkChoiceStore;
pub use persisted_fork_choice::PersistedForkChoice;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
