# ocsp-hosts

Let's Encrypt has announced their intent to [stop providing OCSP service](https://news.ycombinator.com/item?id=41046956).

This contains a list of known OCSP hostnames as observed by crt.sh. 

- VERIFY BEFORE USING, THIS MAY BREAK THINGS
- The file will be periodically updated
- Edit `exclude.txt` to include any exceptions needed
- File is formatted to be used as a blocklist
- Ensure that you understand the difference between fail-open and fail-close behavior
