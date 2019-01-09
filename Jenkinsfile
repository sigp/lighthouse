pipeline {
    agent { dockerfile true }
    stages {
        stage('build') {
            steps {
                sh 'cargo build'
            }
        }
    }
}
