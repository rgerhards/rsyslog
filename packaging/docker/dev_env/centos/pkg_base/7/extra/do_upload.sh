#!/bin/sh
# Definitions common to these scripts
source $(dirname "$0")/config.sh

BRANCHES="v5-stable v7-stable v8-stable testing"

echo "-------------------------------------"
echo "--- Upload RPM Packages               ---"
echo "-------------------------------------"

if [ -z $RPM_REPO ]; then
	echo "Which REPO do you want to upload?--"
	select szSubRepo in $REPOOPTIONS
	do
		break;
	done
else
	echo "REPO is set to '$RPM_REPO'"
	szSubRepo=$RPM_REPO
fi

echo "Uploading Branch '$szYumRepoDir/$szSubRepo/' to $REPOUSERNAME@$REPOURL/$szSubRepo/
"

rsync -au -e "ssh -i /private-files/.ssh/id_rsa" --progress $szYumRepoDir/$szSubRepo/* $REPOUSERNAME@$REPOURL/$szSubRepo/
