#!groovy

pipeline {
  agent { label 'ecs-builder' }

  options {
    ansiColor('xterm')
    timestamps()
  }

  stages {
    stage('publish prerelease') {
      when { not { branch 'master' } }
      steps {
        publishNpmPackagePreRelease('.')
      }
    }

    stage('publish') {
      when { branch 'master' }
      steps {
        publishNpmPackage('.')
      }
    }
  }
}
