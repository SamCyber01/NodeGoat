pipeline {
    agent any
    environment {
        // Define your credentials
        DOCKERHUB_CREDENTIALS = credentials('DockerLogin')
        SNYK_CREDENTIALS = credentials('SnykToken')
        SSH_KEY = credentials('DeploymentSSHKey')
    }
    stages {
        stage('Secret Scanning with TruffleHog') {
            steps {
                script {
                    // SSH Login to server and run TruffleHog
                    sshagent([SSH_KEY]) {
                        sh "telsec@192.168.0.102 'trufflehog --json --exit-code 1 <your-git-repo-url>' > trufflehog-output.json"
                    }
                    // Check for high or critical severity in TruffleHog output
                    def trufflehogOutput = readJSON file: 'trufflehog-output.json'
                    if (trufflehogOutput.any { it.severity == 'high' || it.severity == 'critical' }) {
                        error("High or critical severity issue found in TruffleHog scan")
                    }
                }
            }
        }
        stage('SCA with Snyk and Retire.js') {
            steps {
                script {
                    // Authenticate with Snyk
                    sh "snyk auth ${SNYK_CREDENTIALS}"

                    // Snyk scan
                    sh "snyk test --json > snyk-output.json"
                    def snykOutput = readJSON file: 'snyk-output.json'
                    if (snykOutput.vulnerabilities.any { it.severity == 'high' || it.severity == 'critical' }) {
                        error("High or critical severity issue found in Snyk SCA scan")
                    }

                    // Retire.js scan
                    sh "retire --outputformat json > retire-output.json"
                    def retireOutput = readJSON file: 'retire-output.json'
                    if (retireOutput.any { it.severity == 'high' || it.severity == 'critical' }) {
                        error("High or critical severity issue found in Retire.js scan")
                    }
                }
            }
        }

        stage('SAST with Snyk') {
            steps {
                script {
                    // SAST scan
                    sh "snyk code test --severity-threshold=high > snyk-code-output.json"
                    def snykCodeOutput = readJSON file: 'snyk-code-output.json'
                    if (snykCodeOutput.any { it.severity == 'high' || it.severity == 'critical' }) {
                        error("High or critical severity issue found in Snyk SAST scan")
                    }
                }
            }
        }
    }
    post {
        always {
            // Clean up, logout from Snyk, etc.
        }
    }
}
