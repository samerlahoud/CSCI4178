# scrambler: pseudocode excerpt (instructor-held fallback)

Hand this to a pair **only** when they cannot get Ghidra running, and only
after they have completed Checkpoint 1 and told you what they found. It puts
them back on the same footing as a pair with a working decompiler: it is code
to read and explain, not an answer sheet. The checkpoints are unchanged, and
the evidence standard is unchanged.

This is a **representative decompiler view** written in Ghidra's idiom. It is
not a verbatim capture, and the generated names are placeholders of the kind
Ghidra invents. Do not present it as the literal tool output.

```c
undefined8 main(void)

{
  int    local_118;          // loop counter
  int    local_114;          // length of the line
  char   local_110;          // temporary byte
  char   acStack_108 [256];  // the line buffer
  FILE  *local_8;
  FILE  *local_10;

  local_8 = fopen("message.txt", "r");
  if (local_8 == (FILE *)0x0) { perror("message.txt"); return 1; }

  local_10 = fopen("message.scr", "wb");
  if (local_10 == (FILE *)0x0) { perror("message.scr"); fclose(local_8); return 1; }

  if (fgets(acStack_108, 0x100, local_8) == (char *)0x0) {
    fprintf(*(FILE **)___stderrp, "Error: could not read message.\n");
    ...
    return 1;
  }

  sVar1 = strcspn(acStack_108, "\n");
  acStack_108[sVar1] = '\0';
  local_114 = (int)strlen(acStack_108);

  /* ---- first loop ---- */
  for (local_118 = 0; local_118 < local_114 / 2; local_118 = local_118 + 1) {
    local_110 = acStack_108[local_118];
    acStack_108[local_118] = acStack_108[(local_114 - local_118) + -1];
    acStack_108[(local_114 - local_118) + -1] = local_110;
  }

  /* ---- second loop ---- */
  for (local_118 = 0; local_118 < local_114; local_118 = local_118 + 1) {
    acStack_108[local_118] = acStack_108[local_118] ^ 0x5a;
  }

  fwrite(acStack_108, 1, (long)local_114, local_10);
  fclose(local_8);
  fclose(local_10);
  return 0;
}
```

## What a pair still has to do

Reading this is not the deliverable. They still owe you:

- Why the first loop's bound is `local_114 / 2` and the second loop's is
  `local_114`, and what that difference proves about the two jobs.
- Which of the two axes from slide 13 each loop controls.
- That `0x5a` is a fixed constant and does not depend on the index, and what
  would change if it did.
- The recovered line, and a round-trip check that reproduces `message.scr`
  byte for byte.
