#[macro_export]
macro_rules! crit {
    // Name / target / parent.
    (name: $name:expr, target: $target:expr, parent: $parent:expr, { $($field:tt)* }, $($arg:tt)* ) => (
        tracing::event!(name: $name, target: $target, parent: $parent, tracing::Level::ERROR, { error_type = "crit", $($field)* }, $($arg)*)
    );
    (name: $name:expr, target: $target:expr, parent: $parent:expr, $($k:ident).+ $($field:tt)* ) => (
        tracing::event!(name: $name, target: $target, parent: $parent, tracing::Level::ERROR, { error_type = "crit", $($k).+ $($field)* })
    );
    (name: $name:expr, target: $target:expr, parent: $parent:expr, ?$($k:ident).+ $($field:tt)* ) => (
        tracing::event!(name: $name, target: $target, parent: $parent, tracing::Level::ERROR, { error_type = "crit", ?$($k).+ $($field)* })
    );
    (name: $name:expr, target: $target:expr, parent: $parent:expr, %$($k:ident).+ $($field:tt)* ) => (
        tracing::event!(name: $name, target: $target, parent: $parent, tracing::Level::ERROR, { error_type = "crit", %$($k).+ $($field)* })
    );
    (name: $name:expr, target: $target:expr, parent: $parent:expr, $($arg:tt)+ ) => (
        tracing::event!(name: $name, target: $target, parent: $parent, tracing::Level::ERROR, { error_type = "crit" }, $($arg)+)
    );

    // Name / target.
    (name: $name:expr, target: $target:expr, { $($field:tt)* }, $($arg:tt)* ) => (
        tracing::event!(name: $name, target: $target, tracing::Level::ERROR, { error_type = "crit", $($field)* }, $($arg)*)
    );
    (name: $name:expr, target: $target:expr, $($k:ident).+ $($field:tt)* ) => (
        tracing::event!(name: $name, target: $target, tracing::Level::ERROR, { error_type = "crit", $($k).+ $($field)* })
    );
    (name: $name:expr, target: $target:expr, ?$($k:ident).+ $($field:tt)* ) => (
        tracing::event!(name: $name, target: $target, tracing::Level::ERROR, { error_type = "crit", ?$($k).+ $($field)* })
    );
    (name: $name:expr, target: $target:expr, %$($k:ident).+ $($field:tt)* ) => (
        tracing::event!(name: $name, target: $target, tracing::Level::ERROR, { error_type = "crit", %$($k).+ $($field)* })
    );
    (name: $name:expr, target: $target:expr, $($arg:tt)+ ) => (
        tracing::event!(name: $name, target: $target, tracing::Level::ERROR, { error_type = "crit" }, $($arg)+)
    );

    // Target / parent.
    (target: $target:expr, parent: $parent:expr, { $($field:tt)* }, $($arg:tt)* ) => (
        tracing::event!(target: $target, parent: $parent, tracing::Level::ERROR, { error_type = "crit", $($field)* }, $($arg)*)
    );
    (target: $target:expr, parent: $parent:expr, $($k:ident).+ $($field:tt)* ) => (
        tracing::event!(target: $target, parent: $parent, tracing::Level::ERROR, { error_type = "crit", $($k).+ $($field)* })
    );
    (target: $target:expr, parent: $parent:expr, ?$($k:ident).+ $($field:tt)* ) => (
        tracing::event!(target: $target, parent: $parent, tracing::Level::ERROR, { error_type = "crit", ?$($k).+ $($field)* })
    );
    (target: $target:expr, parent: $parent:expr, %$($k:ident).+ $($field:tt)* ) => (
        tracing::event!(target: $target, parent: $parent, tracing::Level::ERROR, { error_type = "crit", %$($k).+ $($field)* })
    );
    (target: $target:expr, parent: $parent:expr, $($arg:tt)+ ) => (
        tracing::event!(target: $target, parent: $parent, tracing::Level::ERROR, { error_type = "crit" }, $($arg)+)
    );

    // Name / parent.
    (name: $name:expr, parent: $parent:expr, { $($field:tt)* }, $($arg:tt)* ) => (
        tracing::event!(name: $name, parent: $parent, tracing::Level::ERROR, { error_type = "crit", $($field)* }, $($arg)*)
    );
    (name: $name:expr, parent: $parent:expr, $($k:ident).+ $($field:tt)* ) => (
        tracing::event!(name: $name, parent: $parent, tracing::Level::ERROR, { error_type = "crit", $($k).+ $($field)* })
    );
    (name: $name:expr, parent: $parent:expr, ?$($k:ident).+ $($field:tt)* ) => (
        tracing::event!(name: $name, parent: $parent, tracing::Level::ERROR, { error_type = "crit", ?$($k).+ $($field)* })
    );
    (name: $name:expr, parent: $parent:expr, %$($k:ident).+ $($field:tt)* ) => (
        tracing::event!(name: $name, parent: $parent, tracing::Level::ERROR, { error_type = "crit", %$($k).+ $($field)* })
    );
    (name: $name:expr, parent: $parent:expr, $($arg:tt)+ ) => (
        tracing::event!(name: $name, parent: $parent, tracing::Level::ERROR, { error_type = "crit" }, $($arg)+)
    );

    // Name.
    (name: $name:expr, { $($field:tt)* }, $($arg:tt)* ) => (
        tracing::event!(name: $name, tracing::Level::ERROR, { error_type = "crit",$($field)* }, $($arg)*)
    );
    (name: $name:expr, $($k:ident).+ $($field:tt)* ) => (
        tracing::event!(name: $name, tracing::Level::ERROR, {error_type = "crit", $($k).+ $($field)* })
    );
    (name: $name:expr, ?$($k:ident).+ $($field:tt)* ) => (
        tracing::event!(name: $name, tracing::Level::ERROR, { error_type = "crit",?$($k).+ $($field)* })
    );
    (name: $name:expr, %$($k:ident).+ $($field:tt)* ) => (
        tracing::event!(name: $name, tracing::Level::ERROR, { error_type = "crit",%$($k).+ $($field)* })
    );
    (name: $name:expr, $($arg:tt)+ ) => (
        tracing::event!(name: $name, tracing::Level::ERROR, {error_type = "crit"}, $($arg)+)
    );

    // Target.
    (target: $target:expr, { $($field:tt)* }, $($arg:tt)* ) => (
        tracing::event!(target: $target, tracing::Level::ERROR, { error_type = "crit",$($field)* }, $($arg)*)
    );
    (target: $target:expr, $($k:ident).+ $($field:tt)* ) => (
        tracing::event!(target: $target, tracing::Level::ERROR, { error_type = "crit",$($k).+ $($field)* })
    );
    (target: $target:expr, ?$($k:ident).+ $($field:tt)* ) => (
        tracing::event!(target: $target, tracing::Level::ERROR, {error_type = "crit", ?$($k).+ $($field)* })
    );
    (target: $target:expr, %$($k:ident).+ $($field:tt)* ) => (
        tracing::event!(target: $target, tracing::Level::ERROR, {error_type = "crit", %$($k).+ $($field)* })
    );
    (target: $target:expr, $($arg:tt)+ ) => (
        tracing::event!(target: $target, tracing::Level::ERROR, {error_type = "crit"}, $($arg)+)
    );

    // Parent.
    (parent: $parent:expr, { $($field:tt)+ }, $($arg:tt)+ ) => (
        tracing::event!(
            target: module_path!(),
            parent: $parent,
            tracing::Level::ERROR,
            { error_type = "crit", $($field)+ },
            $($arg)+
        )
    );
    (parent: $parent:expr, $($k:ident).+ = $($field:tt)*) => (
        tracing::event!(
            target: module_path!(),
            parent: $parent,
            tracing::Level::ERROR,
            { error_type = "crit", $($k).+ = $($field)* }
        )
    );
    (parent: $parent:expr, ?$($k:ident).+ = $($field:tt)*) => (
        tracing::event!(
            target: module_path!(),
            parent: $parent,
            tracing::Level::ERROR,
            { error_type = "crit", ?$($k).+ = $($field)* }
        )
    );
    (parent: $parent:expr, %$($k:ident).+ = $($field:tt)*) => (
        tracing::event!(
            target: module_path!(),
            parent: $parent,
            tracing::Level::ERROR,
            { error_type = "crit", %$($k).+ = $($field)* }
        )
    );
    (parent: $parent:expr, $($k:ident).+, $($field:tt)*) => (
        tracing::event!(
            target: module_path!(),
            parent: $parent,
            tracing::Level::ERROR,
            { error_type = "crit", $($k).+, $($field)* }
        )
    );
    (parent: $parent:expr, ?$($k:ident).+, $($field:tt)*) => (
        tracing::event!(
            target: module_path!(),
            parent: $parent,
            tracing::Level::ERROR,
            { error_type = "crit", ?$($k).+, $($field)* }
        )
    );
    (parent: $parent:expr, %$($k:ident).+, $($field:tt)*) => (
        tracing::event!(
            target: module_path!(),
            parent: $parent,
            tracing::Level::ERROR,
            { error_type = "crit", %$($k).+, $($field)* }
        )
    );
    (parent: $parent:expr, $($arg:tt)+) => (
        tracing::event!(
            target: module_path!(),
            parent: $parent,
            tracing::Level::ERROR,
            { error_type = "crit" },
            $($arg)+
        )
    );


    ({ $($field:tt)+ }, $($arg:tt)+ ) => (
        tracing::event!(
            target: module_path!(),
            tracing::Level::ERROR,
            { error_type = "crit", $($field)+ },
            $($arg)+
        )
    );
    ($($k:ident).+ = $($field:tt)*) => (
        tracing::event!(
            target: module_path!(),
            tracing::Level::ERROR,
            { error_type = "crit", $($k).+ = $($field)* }
        )
    );
    (?$($k:ident).+ = $($field:tt)*) => (
        tracing::event!(
            target: module_path!(),
            tracing::Level::ERROR,
            { error_type = "crit", ?$($k).+ = $($field)* }
        )
    );
    (%$($k:ident).+ = $($field:tt)*) => (
        tracing::event!(
            target: module_path!(),
            tracing::Level::ERROR,
            { error_type = "crit", %$($k).+ = $($field)* }
        )
    );
    ($($k:ident).+, $($field:tt)*) => (
        tracing::event!(
            target: module_path!(),
            tracing::Level::ERROR,
            { error_type = "crit", $($k).+, $($field)* }
        )
    );
    (?$($k:ident).+, $($field:tt)*) => (
        tracing::event!(
            target: module_path!(),
            tracing::Level::ERROR,
            { error_type = "crit", ?$($k).+, $($field)* }
        )
    );
    (%$($k:ident).+, $($field:tt)*) => (
        tracing::event!(
            target: module_path!(),
            tracing::Level::ERROR,
            { error_type = "crit", %$($k).+, $($field)* }
        )
    );
    (?$($k:ident).+) => (
        tracing::event!(
            target: module_path!(),
            tracing::Level::ERROR,
            { error_type = "crit", ?$($k).+ }
        )
    );
    (%$($k:ident).+) => (
        tracing::event!(
            target: module_path!(),
            tracing::Level::ERROR,
            { error_type = "crit", %$($k).+ }
        )
    );
    ($($k:ident).+) => (
        tracing::event!(
            target: module_path!(),
            tracing::Level::ERROR,
            { error_type = "crit", $($k).+ }
        )
    );

    ($($arg:tt)+) => (
        tracing::event!(
            target: module_path!(),
            tracing::Level::ERROR,
            { error_type = "crit" },
            $($arg)+
        )
    );

}
