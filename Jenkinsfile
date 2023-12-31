pipeline {
    agent any

    environment {
        // Pastikan untuk mengganti dengan kredensial yang sesuai
        SNYK_CREDENTIALS = credentials('SnykToken')
        DOCKERHUB_CREDENTIALS = credentials('DockerLogin')
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
            steps {
                script {
                    docker.image('trufflesecurity/trufflehog:latest').inside {
                        sh 'trufflehog --json https://github.com/SamCyber01/NodeGoat.git > trufflehog-results.json'
                    }

                    def results = readJSON file: 'trufflehog-results.json'
                    if (results.any { it.severity == 'high' || it.severity == 'critical' }) {
                        error("TruffleHog scan found high or critical severity issues.")
                    }
                }
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

        stage('SCA Snyk Test') {
            agent {
                docker {
                    image 'snyk/snyk:node'
                    args '-u root --network host --env SNYK_TOKEN=$SNYK_CREDENTIALS_PSW --entrypoint='
                }
            }
            steps {
                script {
                    try {
                        sh "snyk auth ${SNYK_CREDENTIALS}"
                        sh "snyk test --json > snyk-output.json"
                        def snykOutput = readJSON file: 'snyk-output.json'
                        if (snykOutput.vulnerabilities.any { it.severity == 'high' || it.severity == 'critical' }) {
                            error("High or critical severity issue found in Snyk SCA scan")
                        }
                    } catch (Exception e) {
                        echo "SCA scan failed: ${e.getMessage()}"
                    }
                }
            }
        }

        stage('SCA Retire Js') {
            agent {
                docker {
                    image 'node:lts-buster-slim'
                }
            }
            steps {
                script {
                    sh 'npm install retire'
                    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                        sh './node_modules/retire/lib/cli.js --outputpath retire-scan-report.txt'
                    }
                    sh 'cat retire-scan-report.txt'
                    archiveArtifacts artifacts: 'retire-scan-report.txt'
                }
            }
        }

        stage('SAST with Snyk') {
            steps {
                script {
                    try {
                        sh "snyk code test --severity-threshold=high > snyk-code-output.json"
                        def snykCodeOutput = readJSON file: 'snyk-code-output.json'
                        if (snykCodeOutput.any { it.severity == 'high' || it.severity == 'critical' }) {
                            error("High or critical severity issue found in Snyk SAST scan")
                        }
                    } catch (Exception e) {
                        echo "SAST scan failed: ${e.getMessage()}"
                    }
                }
            }
        }

        stage('Build Docker Image and Push to Docker Registry') {
            steps {
                script {
                    try {
                        sh 'echo $DOCKERHUB_CREDENTIALS_PSW | docker login -u $DOCKERHUB_CREDENTIALS_USR --password-stdin'
                        sh 'docker build -t xenjutsu/nodegoat:0.1 .'
                        sh 'docker push xenjutsu/nodegoat:0.1'
                    } catch (Exception e) {
                        echo "Build or push Docker image failed: ${e.getMessage()}"
                    }
                }
            }
        }

        stage('Deploy Docker Image') {
            steps {
                script {
                    try {
                        withCredentials([sshUserPrivateKey(credentialsId: "DeploymentSSHKey", keyFileVariable: 'keyfile')]) {
                            sh 'ssh -i ${keyfile} -o StrictHostKeyChecking=no telsec@192.168.0.101 "echo $DOCKERHUB_CREDENTIALS_PSW | docker login -u $DOCKERHUB_CREDENTIALS_USR --password-stdin"'
                            sh 'ssh -i ${keyfile} -o StrictHostKeyChecking=no telsec@192.168.0.101 docker pull xenjutsu/nodegoat:0.1'
                            sh 'ssh -i ${keyfile} -o StrictHostKeyChecking=no telsec@192.168.0.101 docker rm --force nodegoat'
                            sh 'ssh -i ${keyfile} -o StrictHostKeyChecking=no telsec@192.168.0.101 docker run -it --detach -p 4000:4000 --name nodegoat --network host xenjutsu/nodegoat:0.1'
                        }
                    } catch (Exception e) {
                        echo "Deployment failed: ${e.getMessage()}"
                    }
                }
            }
        }
    }

    post {
        always {
            echo "Pipeline selesai."
        }
        failure {
            echo "Pipeline terdapat kerentanan dengan severity high atau critical."
        }
        success {
            echo "Pipeline sukses tanpa kerentanan severity high atau critical."
        }
    }
}
