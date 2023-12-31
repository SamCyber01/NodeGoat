pipeline {
    agent any

    environment {
        // Pastikan untuk mengganti dengan kredensial yang sesuai
        SNYK_CREDENTIALS = credentials('SnykToken')
        DOCKERHUB_CREDENTIALS = credentials('DockerLogin')
        TARGET_SERVER = '192.168.0.101'
        IMAGE_NAME = 'jenkins-docker'
        IMAGE_TAG = 'dind'
    }

    stages {
        stage('Secret Scanning with TruffleHog') {
            steps {
                script {
                    try {
                        // Menggunakan TruffleHog dalam container Docker
                        docker.image('trufflesecurity/trufflehog:latest').inside {
                            sh 'trufflehog --json https://github.com/SamCyber01/NodeGoat.git > trufflehog-output.json'
                        }
                        // Analisis output TruffleHog
                        // Tambahkan logika untuk mengecek severity jika diperlukan
                    } catch (Exception e) {
                        echo "TruffleHog scan failed: ${e.getMessage()}"
                    }
                }
            }
        }

        stage('SCA with Snyk and Retire.js') {
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

                        // SCA dengan Retire.js
                        sh "retire --outputformat json > retire-output.json"
                        // Tambahkan logika analisis output dari Retire.js
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
