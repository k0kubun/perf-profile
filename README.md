# perf script: annotate-source

Annotate a source without mixing asm by `perf script report annotate-source`

## Prerequisite

Prepare perf with libpython support. If you're using Ubuntu, you'd need to manually build it:

```
$ git clone --branch=v4.15 https://github.com/torvalds/linux
$ cd linux/tools/perf
$ sudo apt install libpython-dev python-pip
$ make
```

## Installation

Put this repository as `$prefix/libexec/perf-core` where `$prefix` is `$HOME` by default for perf built manually.

```
$ git clone https://github.com/k0kubun/perf-script-annotate-source ~/libexec/perf-core
```

## Usage

Run `perf record` as you like, and run:

```bash
# Annotate all sources
$ perf script report annotate-source

# Annotate a single symbol
$ perf script report annotate-source -- funcname
```

You can also trigger this by `r` at `perf report`.

## License

GNU GPL License version 2
