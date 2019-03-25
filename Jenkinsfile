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
                sh 'cargo build'
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
				sh 'cargo test --all'
			}
		}
    }
}
