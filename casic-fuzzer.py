#!/usr/bin/python3

# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""An example of fuzzing with a custom mutator in Python.

This is a Python translation of the example at:
https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md#example-compression.
"""

import atheris

with atheris.instrument_imports():
  import sys
  import zlib

from time import sleep
def check_sum(length, class_type, msg_id, payload):
        checksum = (msg_id << 24) + (class_type << 16) + length
        for i in range(length/4):
            checksum = checksum + payload[i]
        return checksum

def CustomMutator(data, max_size, seed):
    try:
        msg_header = data[0]
        print("msg_header: ", msg_header)
        
        
        msg_class_type = data[1]
        print("msg_class_type: ", msg_class_type)

        msg_id = data[2]
        print("msg_id: ", msg_id)

        msg_payload = data[3:]
        print("msg_payload: ", msg_payload)

        msg_length = len(msg_payload)
        print("msg_length: ", msg_length)

        msg_checksum = check_sum(msg_length, msg_class_type, msg_id, msg_payload)
        print("msg_checksum: ", msg_checksum)

        final_msg = [msg_header, msg_length, msg_class_type, msg_id, msg_payload, msg_checksum]
    except:
        final_msg =  b"BA CE 00 00 06 00 00 00 06 00"
    else:
        final_msg =  atheris.Mutate(final_msg, len(final_msg))

    return final_msg


    # try:
    #     decompressed = zlib.decompress(data)
    # except zlib.error:
    #     decompressed = b'Hi'
    # else:
    #     decompressed = atheris.Mutate(decompressed, len(decompressed))
    # return zlib.compress(decompressed)


@atheris.instrument_func  # Instrument the TestOneInput function itself
def TestOneInput(data):
    """The entry point for our fuzzer.

    This is a callback that will be repeatedly invoked with different arguments
    after Fuzz() is called.
    We translate the arbitrary byte string into a format our function being fuzzed
    can understand, then call it.

    Args:
    data: Bytestring coming from the fuzzing engine.
    """
    # print("data: ", data)
    if len(data) < 7:
        return
    if data[0] != 0xBA and data[0] != 0xCE:
        return
    sleep(1)

#   try:
#     decompressed = zlib.decompress(data)
#   except zlib.error:
#     return

#   if len(decompressed) < 2:
#     return

#   try:
#     if decompressed.decode() == 'FU':
#       raise RuntimeError('Boom')
#   except UnicodeDecodeError:
#     pass


if __name__ == '__main__':

    atheris.Setup(sys.argv, TestOneInput, custom_mutator=CustomMutator)
    atheris.Fuzz()