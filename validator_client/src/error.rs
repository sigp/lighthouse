use error_chain::error_chain;

error_chain! {
   links  { }

   errors {
    SystemTimeError(t: String ) {
        description("Error reading system time"),
        display("SystemTimeError: '{}'", t)
    }
   }
}
