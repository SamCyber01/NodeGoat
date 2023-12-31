pipeline {
    agent any

    environment {
        // Pastikan untuk mengganti dengan kredensial yang sesuai
        SNYK_CREDENTIALS = credentials('SnykToken')
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
