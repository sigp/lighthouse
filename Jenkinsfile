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
		stage('Test') {
			steps {
				sh 'cargo test --verbose --all'
				sh 'cargo test --verbose --all --release'
			}
		}
	}
}
