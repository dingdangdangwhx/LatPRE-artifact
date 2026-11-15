# Supplementary classical-128 parameter sets

Optional reference data; the paper's frozen L/M/H parameters and measurements are unchanged. E20_10 repeats paper Light.

All selected lattice instances passed all eight pinned MATZOV/GSA attack estimates, including the finite uSVP block scan. Directed spectral/Gaussian checks and 512-bit C-PMF-assisted correctness bounds passed. Security is an underlying-instance attack-cost estimate; correctness assumes ideal sampling. The implementation uses the same approximate OpenFHE-style sampler.

## Selected communication costs (KB)

| Q | M | (k,ell) | ceil(log2 q) | PK | SK | Source CT | RE CT | Rekey |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2^20 | 2^10 | (4,5) | 28 | 8.75 | 7.00 | 3.72 | 1.78 | 52.53 |
| 2^20 | 2^15 | (5,6) | 31 | 11.62 | 9.69 | 4.97 | 1.84 | 87.22 |
| 2^20 | 2^20 | (5,6) | 33 | 12.38 | 10.31 | 5.31 | 2.03 | 92.84 |
| 2^25 | 2^15 | (5,6) | 33 | 12.38 | 10.31 | 5.31 | 2.03 | 92.84 |
| 2^30 | 2^20 | (6,7) | 38 | 16.62 | 14.25 | 7.28 | 2.38 | 99.78 |
| 2^50 | 2^25 | (8,9) | 50 | 28.12 | 25.00 | 12.72 | 3.19 | 225.03 |
| 2^60 | 2^30 | (9,10) | 57 | 35.62 | 32.06 | 16.28 | 3.84 | 320.66 |

Sizes include both key roles and the 32-byte rekey seed; 1 KB = 1024 bytes. Full moduli, widths, compression parameters and bounds are in `parameters.csv` and `selected.json`.

Uncompressed rekeys occupy `32(k+1)k Lg ceil(log2 q) + 32` bytes. E60_30 has k=9, Lg=2 and 57-bit coefficients: 180 ring elements of 1,824 bytes each, plus the seed, give 328,352 bytes (320.66 KB). The usage budget M affects parameter selection through the masking bound; it does not multiply the size of an individual rekey.

## Measured computation costs (ms)

| Profile | Setup | KeyGen | Enc | DecSource | ReKeyGen | Prepare | ReKeyGen + Prepare | ReEnc | DecRE |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| E20_10 | 0.136 | 0.175 | 0.069 | 0.035 | 0.587 | 0.380 | 0.969 | 0.280 | 0.036 |
| E20_15 | 0.248 | 0.240 | 0.094 | 0.050 | 0.927 | 0.646 | 1.631 | 0.372 | 0.047 |
| E20_20 | 0.261 | 0.272 | 0.100 | 0.054 | 1.054 | 0.715 | 1.770 | 0.404 | 0.048 |
| E25_15 | 0.260 | 0.272 | 0.100 | 0.053 | 1.055 | 0.782 | 1.786 | 0.395 | 0.048 |
| E30_20 | 0.383 | 0.364 | 0.127 | 0.070 | 1.025 | 0.750 | 1.772 | 0.442 | 0.061 |
| E50_25 | 0.464 | 0.296 | 0.128 | 0.076 | 1.329 | 1.074 | 2.403 | 0.455 | 0.064 |
| E60_30 | 0.803 | 2.195 | 0.234 | 0.161 | 2.532 | 2.314 | 4.763 | 0.750 | 0.118 |

Single thread, 1,000 measurements after 10 warmups per operation; the table reports medians. ReKeyGen excludes NTT preparation; ReEnc uses a prepared rekey and recomputes its mask. `benchmark.json` and `benchmark-E*.json` retain individual samples and extra diagnostic operations. Added profiles are measured separately; earlier measurements are preserved, with the corresponding numeric-parameter manifests.

## Candidate selection

The finite search first minimizes the sum of source and re-encrypted ciphertext bytes, then permits at most 128 extra bytes for a smaller rekey. The original Light set is retained for the duplicated budget. No global optimum is claimed. The first CBD1 terminal attempt at (Q,M)=(2^20,2^15) was rejected at 127.20 bits; its failed estimate is retained in `security/`.

### E20_10

| Candidate | Base/length | Source (B) | RE (B) | Rekey (B) | Min bits | log2 DFR bound |
| --- | --- | --- | --- | --- | --- | --- |
| frozen-L (selected) | 643/3 | 3808 | 1824 | 53792 | 128.10 | -128.71 |
| a2bf812a03eeca3f35f3 | 129/4 | 3776 | 1696 | 71712 | 128.10 | -128.91 |
| 4589aed439359a31153e | 129/4 | 3680 | 1824 | 71712 | 128.10 | -130.00 |
| fdc8f60f4176dce2e0c4 | 643/3 | 3808 | 1824 | 53792 | 128.10 | -129.04 |

### E20_15

| Candidate | Base/length | Source (B) | RE (B) | Rekey (B) | Min bits | log2 DFR bound |
| --- | --- | --- | --- | --- | --- | --- |
| 7bd3169419939adac951 (selected) | 1287/3 | 5088 | 1888 | 89312 | 132.43 | -129.48 |
| a6d4f16420a4e18e6bd0 | 215/4 | 5088 | 1888 | 119072 | 132.43 | -129.91 |
| 33f66775fadb6ae8b095 | 1287/3 | 5056 | 2016 | 89312 | 132.43 | -128.09 |

### E20_20

| Candidate | Base/length | Source (B) | RE (B) | Rekey (B) | Min bits | log2 DFR bound |
| --- | --- | --- | --- | --- | --- | --- |
| 65a0945da38eb3266eb3 (selected) | 2043/3 | 5440 | 2080 | 95072 | 132.42 | -129.18 |
| c72eba6baf9789dd1060 | 2043/3 | 5504 | 2048 | 95072 | 132.42 | -128.93 |
| b7687a0b7c7d1cbfbf28 | 2043/3 | 5376 | 2240 | 95072 | 132.42 | -130.00 |

### E25_15

| Candidate | Base/length | Source (B) | RE (B) | Rekey (B) | Min bits | log2 DFR bound |
| --- | --- | --- | --- | --- | --- | --- |
| 006736fcf27713f5a1ce (selected) | 2043/3 | 5440 | 2080 | 95072 | 132.42 | -129.77 |
| 9e8220458e7d71cb120b | 2043/3 | 5504 | 2048 | 95072 | 132.42 | -129.67 |
| 6d295eb99f4ca38fbf67 | 2043/3 | 5376 | 2240 | 95072 | 132.42 | -130.00 |

### E30_20

| Candidate | Base/length | Source (B) | RE (B) | Rekey (B) | Min bits | log2 DFR bound |
| --- | --- | --- | --- | --- | --- | --- |
| a63440a0c3cd8443f2f3 | 6481/3 | 7424 | 2432 | 153248 | 133.97 | -129.72 |
| a49a3acd311000d7c735 (selected) | 521661/2 | 7456 | 2432 | 102176 | 133.97 | -129.92 |
| 0f87896b3747096acd5c | 6481/3 | 7392 | 2560 | 153248 | 133.97 | -129.00 |

### E50_25

| Candidate | Base/length | Source (B) | RE (B) | Rekey (B) | Min bits | log2 DFR bound |
| --- | --- | --- | --- | --- | --- | --- |
| 8e65e51eff1b0a0444eb (selected) | 33386239/2 | 13024 | 3264 | 230432 | 136.04 | -128.87 |
| c4aab3e482fe831410ff | 33386239/2 | 12992 | 3296 | 230432 | 136.04 | -128.87 |
| 08ed43265ae3fefec7d1 | 33386239/2 | 12928 | 3488 | 230432 | 136.04 | -130.00 |

### E60_30

| Candidate | Base/length | Source (B) | RE (B) | Rekey (B) | Min bits | log2 DFR bound |
| --- | --- | --- | --- | --- | --- | --- |
| c39cf5bbaac7975d416d (selected) | 377722169/2 | 16672 | 3936 | 328352 | 134.23 | -128.08 |
| 9561a7d4ca11a86679df | 377722169/2 | 16640 | 3968 | 328352 | 134.23 | -128.59 |
| f6413cb81d55249167b0 | 377722169/2 | 16576 | 4224 | 328352 | 134.23 | -129.87 |

## Reproduce

From the artifact root:

```sh
make -C latpre all test
./latpre/build/bench_lbpre --profiles E20_10,E20_15,E20_20,E25_15,E30_20,E50_25,E60_30 --samples 1000 --warmup 10 --all-operations --csv /tmp/extended.csv --json /tmp/extended.json
sage -python params/extended_certify.py --verify-only
```

`params/extended_search.py` reruns the small floating search; `extended_certify.py` performs missing full security/C calculations serially and caches exact instances. `params/export_extended.py` regenerates the named C profiles from the verified selection. Runtime varies with the machine.

For E60_30, wider masks use the existing Karney algorithm with exact integer arithmetic for the proposal origin, avoiding loss of integer units above the binary64 mantissa range. Original L/M/H sampler streams are preserved; finite-precision statistical error remains uncertified.
