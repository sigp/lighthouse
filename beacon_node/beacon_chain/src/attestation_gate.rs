use parking_lot::{Condvar, Mutex};

pub struct AttestationGate {
    mutex: Mutex<bool>,
    condvar: Condvar,
}

impl Default for AttestationGate {
    fn default() -> Self {
        Self {
            mutex: Mutex::new(false),
            condvar: Condvar::new(),
        }
    }
}

impl AttestationGate {
    pub fn prevent_attestation(&self) {
        *self.mutex.lock() = false;
    }

    pub fn allow_attestation(&self) -> usize {
        *self.mutex.lock() = true;
        self.condvar.notify_all()
    }

    pub fn block_until_attestation_permitted(&self) {
        let mut ready = self.mutex.lock();
        while !*ready {
            self.condvar.wait(&mut ready)
        }
    }
}
