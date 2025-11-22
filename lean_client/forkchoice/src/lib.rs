pub mod helpers;

pub use helpers::get_fork_choice_head;

// Note: Store functionality is implemented in `lean_store` crate (`LeanStore` struct)
// rather than as a separate module here. The `LeanStore` provides all persistence
// operations needed for forkchoice operations (blocks, states, attestations, head root, safe target).
