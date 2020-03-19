# perf-profile

Profiling C code with Linux perf made easy

## Prerequisite

Get perf with libpython support.
If you're using Ubuntu, you'd need to manually build it as it's not supported by default:

```
$ git clone --branch=v4.15 https://github.com/torvalds/linux
$ cd linux/tools/perf
$ sudo apt install libpython-dev python-pip
$ make
```

## Installation

Put this repository as `$prefix/libexec/perf-core` where `$prefix` is `$HOME` by default for perf built manually.

```
$ git clone https://github.com/k0kubun/perf-profile ~/libexec/perf-core
```

## Usage

Run `perf record` as you like, and run:

```bash
# Annotate all sources
$ perf script report profile

# Annotate a single symbol
$ perf script -S funcname report profile
```

You can also trigger this by pushing `r` on `perf report`.

## License

GNU GPL License version 2
