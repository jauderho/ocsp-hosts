#!/bin/bash
#
# Fetch known OCSP hosts from https://crt.sh/
#
# Run this at the base directory of your repo
# Make sure to configure .github/dependabot.yml to update "github-actions" in a timely manner
# This may break your setup. Read carefully before running
#
set -euo pipefail
IFS=$'\n\t'

# make sure we have the latest commits
git pull

# fetch from crt.sh
# only parse the lines with potential OCSP hosts
# extract the content
# cleanup to only retain hostnames
# drop bad entries
# drop IP addresses
# normalize
# sort then uniq
# output in hosts format
curl --max-time 180 -sL https://crt.sh/ocsp-responders > /tmp/rawr && \
grep "A title" /tmp/rawr | \
sed -n 's/.*<A[^>]*>\([^<]*\)<\/A>.*/\1/p' | \
sed -e 's#https\?://##' -e 's#hhtp://##' -e 's#:[0-9]*##' -e "s#/.*##" | \
grep -iEv "ldap:|url=|uri=|uri:" | \
grep -v "\.$" | \
grep -Ev '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
tr '[:upper:]' '[:lower:]' | \
tr -cd '[:alnum:]-.\n' | \
sort -u | \
sed -e 's#^#0.0.0.0 #' > ocsp-hosts && \
rm /tmp/rawr
