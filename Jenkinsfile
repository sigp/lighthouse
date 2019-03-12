pipeline {
    agent {
		dockerfile {
			filename 'Dockerfile'
			args '-v cargo-cache:/cargocache:rw'
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
                sh 'cargo clippy'
            }
        }
        stage('Test') {
			steps {
				sh 'cargo test --all'
			}
		}
    }
}
