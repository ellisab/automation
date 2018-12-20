
// Run on jenkins.caasp.suse.net, use KVM

pipeline {
    agent any
    stages {
        stage('Run') {
            steps {
                sh "rm ${WORKSPACE} -rf"
                sh "git clone --depth 1 -b pytest https://github.com/kubic-project/automation.git"
                withCredentials([
                  file(credentialsId: 'caasp-bare-metal-conf', variable: 'BMCONF'),
                  usernamePassword(credentialsId: 'github-token-caaspjenkins', passwordVariable: 'GH-CAASPJENKINS-PASS', usernameVariable: 'GH-CAASPJENKINS-USER'),
                  usernamePassword(credentialsId: 'github-token', passwordVariable: 'GITHUB-TOKEN', usernameVariable: 'GITHUB-USER')
                ]) {
                    // no collab check: do not use for PRs
                    sh "automation/misc-tools/test_kubic/testrunner change-author=nobody no-collab-check vanilla"
                }
            }
        }
    }
}


