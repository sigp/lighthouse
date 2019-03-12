pipeline {
    agent {
		dockerfile {
			filename 'Dockerfile'
			args '-v cargo-cache:/cargocache:rw -e "CARGO_HOME=/cargocache"'
		}
	}
    stages {
        stage('Check') {
            steps {
                sh 'cargo fmt --all -- --check'
            }
        }
        stage('Build') {
            steps {
                sh 'cargo build'
            }
        }
        stage('Test') {
			steps {
				sh 'cargo test --all'
			}
		}
    }
}
