import json 
import argparse
import datetime
import sys

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def print_label(label, value):
    print(label + " = " + value)

def parse_ascon_aead128_tests(groups):
    for grp in groups:
        for tst in grp['tests']:
            print("")
            print_label("tcID", str(tst["tcId"]))
            print_label("Key", tst["key"])
            if 'secondKey' in tst:
                print_label("SecondKey", tst["secondKey"])
            print_label("IV", tst["nonce"])
            print_label("AAD", tst["ad"])
            print_label("Tag", tst["tag"])
            print_label("Plaintext", tst["pt"])
            print_label("Ciphertext", tst["ct"])
            print_label("Reason", tst["reason"])


parser = argparse.ArgumentParser(description="")
parser.add_argument('filename', type=str, help='Input JSON file')
args = parser.parse_args()

with open(args.filename, 'r') as file:
    data = json.load(file)

year = datetime.date.today().year
version = data['vsId']
algorithm = data['algorithm']
mode = data['mode']
revision = data['revision']

print("# Copyright " + str(year) + " The OpenSSL Project Authors. All Rights Reserved.")
print("#")
print("# Licensed under the Apache License 2.0 (the \"License\").  You may not use")
print("# this file except in compliance with the License.  You can obtain a copy")
print("# in the file LICENSE in the source distribution or at")
print("# https://www.openssl.org/source/license.html\n")
print("# ACVP test data for " + algorithm + " " + mode + " generated from")
print("# https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/json-files/"
      + algorithm + "-" + mode + "-" + revision + "/internalProjection.json")
print("# [version " + str(version) + "]")

print("")
print_label("Title", algorithm + " " + mode + " ACVP Tests")

if algorithm == "Ascon":
    if mode == "AEAD128":
        print("")
        print("Ascon-AEAD128 Test Vectors: ")
        parse_ascon_aead128_tests(data['testGroups'])
    else:
        eprint("Unsupported mode: " + mode)
else:
    eprint("Unsupported algorithm: " + algorithm)