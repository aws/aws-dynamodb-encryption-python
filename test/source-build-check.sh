#!/bin/bash
# Verify that tests can be successfully run from the source build.
#
#NOTE: Humans should not run this file directly. If you want to run this check, use the
#   tox to run the "sourcebuildcheck" test environment.

WORKINGDIR=${1}
DISTDIR=${2}

echo "Performing source build check"
echo "Using working directory ${WORKINGDIR}"
echo "Using dist directory ${DISTDIR}"

echo "Locating the source build and copying it into the working directory."
DISTFILE=$(ls ${DISTDIR}/dynamodb-encryption-sdk-*.tar.gz | tail -1)
echo "Found source build at ${DISTFILE}"
cp ${DISTFILE} ${WORKINGDIR}

echo "Extracting the source build."
cd ${WORKINGDIR}
NEWDISTFILE=$(ls dynamodb-encryption-sdk-*.tar.gz | tail -1)
echo "Using distfile ${NEWDISTFILE}"
tar xzvf ${NEWDISTFILE}
rm ${NEWDISTFILE}
EXTRACTEDDIR=$(ls | tail -1)
cd ${EXTRACTEDDIR}

echo "Installing requirements from extracted source build."
pip install -r dev_requirements/test-requirements.txt
pip install -e .

echo "Running tests from extracted source build."
pytest --cov dynamodb_encryption_sdk -m "local and not slow and not veryslow and not nope"
