pipeline {
  agent any
  stages {
    stage('build package') {
      steps {
        sh 'make package_deb'
      }
    }
  }
}