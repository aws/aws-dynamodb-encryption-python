#!/bin/bash
# Verify that tests can be successfully run from the source build.
#
#NOTE: Humans should not run this file directly. If you want to run this check, use the
#   tox to run the "sourcebuildcheck" test environment.

WORKINGDIR=$1
DISTDIR=$2

echo "Locating the source build and copying it into the working directory."
DISTFILE=`ls $DISTDIR/dynamodb-encryption-sdk-*.tar.gz | tail -1`
cp $DISTFILE $WORKINGDIR
DISTFILE=`ls $WORKINGDIR/dynamodb-encryption-sdk-*.tar.gz | tail -1`

echo "Extracting the source build."
cd $WORKINGDIR
tar xzvf $DISTFILE
rm $DISTFILE
EXTRACTEDDIR=`ls | tail -1`
cd $EXTRACTEDDIR

echo "Installing requirements from extracted source build."
pip install -r test/requirements.txt
pip install -e .

echo "Running tests from extracted source build."
pytest --cov dynamodb_encryption_sdk -m "local and not slow and not veryslow and not nope"
