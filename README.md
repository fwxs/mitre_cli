# Mitre_cli

An oxidized Mitre Framework's scraper.

## Overview

This project was created for two reasons:

1. Develop a CLI that allowed an easy interaction with Mitre Frameworks through the terminal, mainly ATT&CK.
2. Practice Rust on my spare time.

## Usage

Mitre-cli attack main section

```bash
$ mitre_cli attack --help
Mitre ATT&CK Framework scraper sub-menu

USAGE:
    mitre_cli attack <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    describe    Retrieve ATT&CK entity information (Name, Description and associated data)
    help        Prints this message or the help of the given subcommand(s)
    list        List Mitre ATT&CK entities
```

## TODOs

- [x] ~Scrape ATT&CK~
- [x] Save an offline version of the scraped data
- [ ] Scrape other frameworks