# r17_reader: pseudocode excerpt (instructor-held fallback)

Hand this to a pair **only** when they cannot get Ghidra running, and only
after they have completed Checkpoint 1 and told you what they found. It puts
them back on the same footing as a pair with a working decompiler: it is code
to read and explain, not an answer sheet. The checkpoints are unchanged, and
the evidence standard is unchanged.

This is a **representative decompiler view** written in Ghidra's idiom. It is
not a verbatim capture, and the generated names are placeholders of the kind
Ghidra invents. Do not present it as the literal tool output.

```c
undefined8 main(int param_1, long param_2)

{
  uint   uVar1;
  uint   local_1c;          // loop counter
  uint   local_18;          // length taken from the file
  byte   local_14;          // 8-bit accumulator
  uint   local_10;          // running total over the output array
  size_t local_8;           // bytes actually read
  byte   auStack_88 [128];  // raw file bytes
  byte   auStack_48 [96];   // second array, written later

  if (param_1 != 2) {
    fprintf(stderr, "Usage: %s FILE\n", *param_2);
    return 2;
  }

  pFVar1 = fopen(*(char **)(param_2 + 8), "rb");
  if (pFVar1 == NULL) { perror(*(char **)(param_2 + 8)); return 2; }
  local_8 = fread(auStack_88, 1, 128, pFVar1);
  ...
  fclose(pFVar1);

  /* ---- first group of checks ---- */
  if ((local_8 < 7) || (memcmp(auStack_88, "R4178", 5) != 0)) {
    fprintf(stderr, "Invalid header\n");
    return 1;
  }

  local_18 = (uint)auStack_88[5];
  if (((local_18 == 0) || (0x50 < local_18)) || (local_8 != local_18 + 7)) {
    fprintf(stderr, "Invalid length\n");
    return 1;
  }

  /* ---- first loop ---- */
  local_14 = 0;
  for (local_1c = 0; local_1c < local_18; local_1c = local_1c + 1) {
    local_14 = local_14 + auStack_88[local_1c + 6];
  }
  if (local_14 != auStack_88[local_18 + 6]) {
    fprintf(stderr, "Invalid checksum\n");
    return 1;
  }

  /* ---- second loop ---- */
  for (local_1c = 0; local_1c < local_18; local_1c = local_1c + 1) {
    auStack_48[(local_18 - local_1c) - 1] =
         auStack_88[local_1c + 6] ^ (byte)(local_1c % 5) + 0x23;
  }
  auStack_48[local_18] = 0;

  local_10 = 0;
  for (local_1c = 0; local_1c < local_18; local_1c = local_1c + 1) {
    local_10 = local_10 + auStack_48[local_1c];
  }
  printf("Accepted: %u characters; character sum=%u\n", local_18, local_10);
  return 0;
}
```

## What a pair still has to do

Reading this is not the deliverable. They still owe you:

- Which byte is the length, and what independent fact confirms it
  (`0x50` is 80, the upper bound, not the length).
- Why `local_14` wrapping at 8 bits is the same as modulo 256.
- Which loop rejects `bad_checksum.r17`, and why the payload is irrelevant to
  that rejection.
- That the destination index runs backwards while the source index runs
  forwards, and that this is separate from the XOR.
- A working decoder and a character sum of 3574.
