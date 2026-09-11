# ocsp-hosts

Let's Encrypt has announced their intent to [stop providing OCSP service](https://news.ycombinator.com/item?id=41046956).

This contains a list of known OCSP hostnames as observed by crt.sh. 

- VERIFY BEFORE USING, THIS MAY BREAK THINGS
- The file is refreshed on the 1st of every month by the `Refresh OCSP Hosts` workflow
- Edit `exclude.txt` to include any exceptions needed; one extended regex per line, `#` starts a comment
- File is formatted to be used as a blocklist
- Ensure that you understand the difference between fail-open and fail-close behavior

To regenerate the list by hand, run `scripts/refreshOCSPHosts.sh` from the repo
root. Use `--dryrun` to preview the change and `--help` for the full option list.
