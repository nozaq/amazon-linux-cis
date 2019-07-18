# amazon-linux-cis

[![CircleCI](https://circleci.com/gh/nozaq/amazon-linux-cis.svg?style=svg)](https://circleci.com/gh/nozaq/amazon-linux-cis)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/34bfe0c895814295a863a09c30437d34)](https://www.codacy.com/app/nozaq/amazon-linux-cis?utm_source=github.com&utm_medium=referral&utm_content=nozaq/amazon-linux-cis&utm_campaign=badger)

Bootstrap script for Amazon Linux to comply with [CIS Amazon Linux Benchmark v2.0.0](https://www.cisecurity.org/benchmark/amazon_linux/).

## Usage
```
$ git clone git@github.com:nozaq/amazon-linux-cis.git .
$ python ./amazon-linux-cis
```

## Available Arguments
Argument (default value) | What it does 
------------ | -------------
--time (169.254.169.123) | Specify the upstream time server
--chrony *boolean* (true) | Use chrony for time synchronization
--no-backup | Automatic config backup is disabled
--clients *comma seperate list* | Specify a comma separated list of hostnames and host IP addresses
-v --verbose | Enable verbose logging of utility
--disable-tcp-wrappers | Disable installation of TCP Wrappers package
--disable-pam | Disable installation of TCP Wrappers package
--disable-iptables | Disable the hardening of the PAM module
--disable-mount-options | Disable replacing the default */etc/fstab* mounting config file


## Amazon Linux 2 Support
Although the differences between Amazon Linux and Amazon Linux 2 are extensive ([listed here](https://aws.amazon.com/amazon-linux-2/faqs/)), the majority of the changes to reach CIS compliance for Amazon Linux 2 are minor. Here's the minimum required command line needed to install the hardening on Amazon Linux 2 instances.

```
python ./amazon-linux-cis --disable-mount-options
```

## Tested Environments
- Amazon Linux 2017.09
- Amazon Linux AMI 2018.03.0 (HVM)
- Amazon Linux 2 - 2017.12
