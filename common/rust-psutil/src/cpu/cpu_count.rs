use crate::Count;

pub fn cpu_count() -> Count {
	num_cpus::get() as Count
}

pub fn cpu_count_physical() -> Count {
	num_cpus::get_physical() as Count
}
