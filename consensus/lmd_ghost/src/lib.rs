mod fork_choice;
mod fork_choice_store;

pub use fork_choice::{Error, ForkChoice};
pub use fork_choice_store::ForkChoiceStore;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
