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
            agent {
                docker {
                    image 'trufflesecurity/trufflehog:latest'
                    args '-u root --entrypoint='
                }
            }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh 'trufflehog filesystem . --exclude-paths trufflehog-excluded-paths.txt --fail --json > trufflehog-scan-result.json'
                }
                sh 'cat trufflehog-scan-result.json'
                archiveArtifacts artifacts: 'trufflehog-scan-result.json'
            }
        }
        stage('Build') {
            agent {
                docker {
                    image 'node:lts-buster-slim'
                }
            }
            steps {
                sh 'npm install'
            }
        }
        stage('Test') {
            agent {
                docker {
                    image 'node:lts-buster-slim'
                }
            }
            steps {
                sh 'npm run test'
            }
        }
        /*
        stage('TruffleHog Scan via SSH') {
            steps {
                script {
                    // SSH Login to server and run TruffleHog
                    sshagent([SSH_KEY]) {
                        sh "ssh telsec@192.168.0.101 'trufflehog --json --exit-code 1 https://github.com/SamCyber01/NodeGoat.git' > trufflehog-output.json"
                    }
                    // Check for high or critical severity in TruffleHog output
                    def trufflehogOutput = readJSON file: 'trufflehog-output.json'
                    if (trufflehogOutput.any { it.severity == 'high' || it.severity == 'critical' }) {
                        error("High or critical severity issue found in TruffleHog scan")
                    }
                }
            }
        }
        */
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
            // Contoh langkah: menampilkan pesan di log
            echo "Pipeline selesai."
        }
        failure {
            // Tindakan jika pipeline gagal
            echo "Pipeline terdapat kerentanan dengan severity high atau critical."
        }
        success {
            // Tindakan jika pipeline sukses
            echo "Pipeline sukses."
        }
    }
}
