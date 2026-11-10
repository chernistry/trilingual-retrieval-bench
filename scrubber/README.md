# text-scrubber

`scrub.py` replaces identifying tokens in text files with stable pseudonyms and
gives each source document a neutral alias. It is a single Python module that
uses only the standard library.

## What it does

1. **Harvest.** Reads a source tree and builds a denylist of identifiers: the
   root directory name, git remotes and authors, package manifests, e-mail
   addresses, domains and host names, ticket prefixes (`ABC-123`), IPv4
   addresses, `@handles`, company names with a legal suffix, and frequent
   capitalised words that are not ordinary English.
2. **Scrub.** Replaces every denylist term in every prose document
   (`.md .markdown .txt .rst .org .adoc`) with a pseudonym such as `<HOST_2>`
   and writes the result under an alias path.
3. **Verify.** Re-scans the output for denylist terms that survived.
4. **Reverse.** Resolves an alias back to its source path through the mapping
   file.

## Guarantees

- Pseudonyms are stable. The same token gets the same pseudonym in every
  document and every run that uses the same mapping file. Existing assignments
  are never renumbered; new terms take the next free number.
- Scrubbing already scrubbed text changes nothing.
- A document whose output still contains a denylist term is refused, not
  written.
- An alias is `scrubbed/<16 hex>/<stem><suffix>`. The hex part is an HMAC of
  the source path under a local random salt. The alias is reversible only
  through the mapping file, which is kept in the state directory, outside the
  output. `scrub` refuses to run if the state directory is inside the output
  directory.

## Install and run

Requires Python 3.10 or newer. There is nothing to install; run the file.
Tests need `pytest`.

```
python3 scrub.py harvest --root NOTES_DIR [--floor 3] [--out FILE]
                         [--background DIR ...] [--paranoid]
python3 scrub.py scrub   --root NOTES_DIR --out OUT_DIR [--denylist FILE] [--strict]
python3 scrub.py verify  --scrubbed OUT_DIR [--denylist FILE] [--include-ambiguous]
python3 scrub.py alias   PATH ... [--denylist FILE]
python3 scrub.py reverse ALIAS ...
```

State (salt, mapping file, default denylist) lives in `~/.config/text-scrubber/`.
Set `SCRUBBER_DIR` to use another directory. The salt and the mapping file are
written with mode 0600. Keep them out of version control and out of anything
you publish together with the output.

Options:

- `--floor N`: a capitalised word must occur `N` times to be denied.
- `--background DIR`: a directory of neutral text. Words that also occur there
  are treated as ordinary vocabulary and not denied.
- `--paranoid`: deny everything harvested; skip the dependency, own-identity
  and background exclusions.
- `--strict`: also replace denylist terms that are ordinary English words
  (by default these are replaced only in identifier context, for example
  `the Beacon service` or `` `Beacon` ``).

Harvesting reads the current user's `~/.gitconfig` to avoid pseudonymising the
user's own name, and reads dependency names from the tree's package manifests
so that public library names are kept.

## Example

```
$ cat notes/docs/deploy.md
# Zorvex rollout

The Zorvex gateway runs on gw-prod.zorvex.example. Contact
dana.rivera@zorvex.example. Tracked as ZRV-120.

$ python3 scrub.py harvest --root notes --floor 1 --out denylist.json
$ python3 scrub.py scrub --root notes --out out --denylist denylist.json
$ cat out/scrubbed/*/deploy.md
# <ORG_2> rollout

The <ORG_2> gateway runs on <HOST_2>. Contact
<EMAIL_1>. Tracked as <TICKET_1>.

$ python3 scrub.py verify --scrubbed out --denylist denylist.json
$ python3 scrub.py reverse scrubbed/8866ee2c6258dc67/deploy.md
/path/to/notes/docs/deploy.md
```

The alias hash differs between salts. The denylist file is itself sensitive: it
lists the identifiers in clear.

## Limits

- It replaces what its rules and dictionaries name. It does not detect every
  identifier. Names of people, products and places that appear only in running
  prose, with no structural source (git author, manifest, e-mail address,
  legal suffix), are caught only if they are frequent capitalised words that
  pass the filters.
- The rules are tuned for English text. The built-in word lists (top-level
  domains, ticket-prefix stop words, technology names) are short and are not
  exhaustive.
- Ordinary English words that are also identifiers are left alone outside
  identifier context unless `--strict` is given.
- It does not look for credentials, personal data in free text, or the content
  of images and binary files. Only prose-suffix files are read.
- Review the denylist and the output before publishing either. `verify` checks
  only for denylist terms.

## Tests

```
python3 -m pytest -q
```

## License

See the `LICENSE` file in the repository root.
