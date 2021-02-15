# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added 2021-02-15
- UsernamePassword credentials are now supported through the use of a `username` tag on the secret

## [1.0.0] - 2019/02/04

This release brings a partial rewrite to use a more modern Jenkins design, this allows automatic support for the configuration as code plugin and simplifies changes going forward. As part of this release free style project support is removed, if someone wants to use this they can send a PR to restore it, I don't use it myself so don't want to keep something around that isn't in use anywhere, especially given the current test coverage of this project.

### New feature:

- Add symbol, DSL now supports `withAzureKeyVault` rather than the more verbose `wrap` form, `wrap` will still work [PR #8](https://github.com/jenkinsci/azure-keyvault-plugin/pull/8)
- Configuration as code support [example](https://github.com/jenkinsci/azure-keyvault-plugin#via-configuration-as-code) [PR #9](https://github.com/jenkinsci/azure-keyvault-plugin/pull/9) [PR #13](https://github.com/jenkinsci/azure-keyvault-plugin/pull/13)
- Add vault url to secret not found message [PR #14](https://github.com/jenkinsci/azure-keyvault-plugin/pull/14)

### Internal:

- Automated code cleanup [PR #6](https://github.com/jenkinsci/azure-keyvault-plugin/pull/6) [PR #7](https://github.com/jenkinsci/azure-keyvault-plugin/pull/7)

## [0.10.0] - 2019/02/02

Initial release under jenkinsci
