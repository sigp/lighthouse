pipeline {
	agent {
		dockerfile {
			filename 'Dockerfile'
			args '-v cargo-cache:/cargocache:rw -e "CARGO_HOME=/cargocache"'
		}
	}
	stages {
		stage('Build') {
			steps {
				sh 'cargo build --verbose --all'
				sh 'cargo build --verbose --all --release'
			}
		}
        stage('Check') {
            steps {
                sh 'cargo fmt --all -- --check'
                // No clippy until later...
                //sh 'cargo clippy'
            }
        }
		stage('Test') {
			steps {
				sh 'cargo test --verbose --all'
				sh 'cargo test --verbose --all --release'
                sh 'cargo test --manifest-path eth2/state_processing/Cargo.toml --verbose \
                               --release --features fake_crypto --ignored'

			}
		}
	}
}
