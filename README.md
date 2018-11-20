# CaaSP Platform Automation

[![Build Status Master branch](https://travis-ci.org/kubic-project/automation.svg?branch=master)](https://travis-ci.org/kubic-project/automation)

The repo houses various tools and automation scripts that are used by the
SUSE Kubic team for dev/test/CI purposes for the **SUSE CaaS Platform Product**.

**NOTE: The tools in this repo should not be used on openSUSE Kubic**

## Table of Content

- [Deployement](#deploy-tools)
- [Tests-and-scheduling-logic](#tests-and-scheduling-logic)
- [Extra](#extra)

___
# Deploy tools

## caasp-devenv

A wrapper script which orchestrates several of the other tools to build,
bootstrap, test etc in a single command. For usage, see it's `--help`
output.

## CaaSP KVM

A tool to build a KVM based development cluster for CaaSP

## CaaSP OpenStack Heat

A tool to build a OpenStack based CaaSP cluster. Well suited to building
large scale clusters for testing and validation.

## CaaSP OpenStack Terraform

A tool to build a OpenStack based CaaSP cluster. Well suited to building
large scale clusters for testing and validation.

## CaaSP Bare Metal

A tool to build a Bare Metal cluster. Acts as a client for the Bare Metal
Manager service.
___
# Tests and scheduling logic

## Jenkins Pipelines

A set of Jenkins pipelines which are not directly associated with a specific
repo. e.g. Nightly builds.

## Kubernetes e2e-tests

Some scripting to run the Kubernetes e2e tests against as a CaaSP cluster

## Testinfra Infrastructure Tests

A set of tests to validate a CaaSP cluster has been successfully deployed

## Velum Bootstrap automation

Some scripting to walk through the Velum UI to bootstrap a cluster, primarily
used within CI.
___
# Extra 

## Development

Where possible, use Python, Ruby, Bash.

Tools should be able to run on developer workstations and in CI runs.
Prefer configurable paths.

CI logs can be difficult to inspect: avoid output that look like
errors if unnecessary. Structure the output with headers and footers if needed.

Common CLI options:
```sh
 -h                help
 -l --logfile      write logs to a file (used to capture logs in CI)
 --outdir          output directory (used to capture artifacts in CI)
 --env-json-path   environment.json file path
```
