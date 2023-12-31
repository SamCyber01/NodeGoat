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
                script {
                    try {
                        // Menggunakan TruffleHog dalam container Docker
                        docker.image('trufflesecurity/trufflehog:latest').inside {
                            sh 'trufflehog --json https://github.com/SamCyber01/NodeGoat.git > trufflehog-output.json'
                        }
                    } catch (Exception e) {
                        echo "TruffleHog scan failed: ${e.getMessage()}"
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
                        // Autentikasi dengan Snyk
                        sh "snyk auth ${SNYK_CREDENTIALS}"
                        // SCA dengan Snyk
                        sh "snyk test --json > snyk-output.json"
                        def snykOutput = readJSON file: 'snyk-output.json'
                        if (snykOutput.vulnerabilities.any { it.severity == 'high' || it.severity == 'critical' }) {
                            error("High or critical severity issue found in Snyk SCA scan")
                        }
        stage('SCA Retire Js') {
            agent {
              docker {
                  image 'node:lts-buster-slim'
              }
            }
            steps {
                sh 'npm install retire'
                catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                    sh './node_modules/retire/lib/cli.js --outputpath retire-scan-report.txt'
                }
                sh 'cat retire-scan-report.txt'
                archiveArtifacts artifacts: 'retire-scan-report.txt'
            }
        }
                        // SCA dengan Retire.js
                        sh "retire --outputformat json > retire-output.json"
                    } catch (Exception e) {
                        echo "SCA scan failed: ${e.getMessage()}"
                    }
                }
            }
        }
        stage('SAST with Snyk') {
            steps {
                script {
                    try {
                        // SAST dengan Snyk
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
        /*
        stage('Build and Push Docker Image') {
            steps {
                script {
                    // Login ke Docker Hub
                    sh "docker login -u ${DOCKERHUB_CREDENTIALS_USR} -p ${DOCKERHUB_CREDENTIALS_PSW}"
                    // Membangun image Docker
                    sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} ."
                    // Push image ke Docker Hub
                    sh "docker push ${IMAGE_NAME}:${IMAGE_TAG}"
                }
            }
        }
        
        stage('Deploy to Server') {
            steps {
                script {
                    try {
                        // Langkah-langkah untuk deploy image ke server target
                        sshagent(credentials: ['SSH_CREDENTIALS_ID']) {
                            // Menarik image Docker di server target
                            sh "ssh -o StrictHostKeyChecking=no ${TARGET_SERVER} 'docker pull ${IMAGE_NAME}:${IMAGE_TAG}'"
                            // Jalankan container Docker di server target
                            sh "ssh -o StrictHostKeyChecking=no ${TARGET_SERVER} 'docker run -d --name my-container-name -p 80:80 ${IMAGE_NAME}:${IMAGE_TAG}'"
                        }
                    } catch (Exception e) {
                        echo "Deployment failed: ${e.getMessage()}"
                    }
                }
            }
        }
        */
        stage('Build Docker Image and Push to Docker Registry') {
            agent {
                docker {
                    image 'docker:dind'
                    args '--user root --network host -v /var/run/docker.sock:/var/run/docker.sock'
                }
            }
            steps {
                sh 'echo $DOCKERHUB_CREDENTIALS_PSW | docker login -u $DOCKERHUB_CREDENTIALS_USR --password-stdin'
                sh 'docker build -t xenjutsu/nodegoat:0.1 .'
                sh 'docker push xenjutsu/nodegoat:0.1'
            }
        }
        stage('Deploy Docker Image') {
            agent {
                docker {
                    image 'kroniak/ssh-client'
                    args '--user root --network host'
                }
            }
            steps {
                withCredentials([sshUserPrivateKey(credentialsId: "DeploymentSSHKey", keyFileVariable: 'keyfile')]) {
                    sh 'ssh -i ${keyfile} -o StrictHostKeyChecking=no jenkins@192.168.0.101 "echo $DOCKERHUB_CREDENTIALS_PSW | docker login -u $DOCKERHUB_CREDENTIALS_USR --password-stdin"'
                    sh 'ssh -i ${keyfile} -o StrictHostKeyChecking=no jenkins@192.168.0.101 docker pull xenjutsu/nodegoat:0.1'
                    sh 'ssh -i ${keyfile} -o StrictHostKeyChecking=no jenkins@192.168.0.101 docker rm --force nodegoat'
                    sh 'ssh -i ${keyfile} -o StrictHostKeyChecking=no jenkins@192.168.0.101 docker run -it --detach -p 4000:4000 --name nodegoat --network host xenjutsu/nodegoat:0.1'
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
