# Reverse engineering workshop: R4178 files

## Situation

You have a small file reader and two files in its private format. The reader
accepts one file and rejects the other. The source and format specification are
unavailable. Your task is to reconstruct enough of the format and the decoding
routine to recover the text in the valid file.

## Provided files

- `r17_reader`: the compiled program
- `note.r17`: a valid data file
- `bad_checksum.r17`: a file the program rejects

## Before you start

**Ghidra** is the disassembler and decompiler for this workshop. It is free,
runs on macOS, Windows and Linux, and needs a JDK 21 or later.

- Download: <https://ghidra-sre.org/>
- If you do not have it working, start with Checkpoint 1 anyway. It needs only
  `hexdump`. Ask for the pseudocode excerpt and you can still do Checkpoints
  2 and 3 from real code.

**Running the reader is optional.** It is a macOS Apple Silicon executable, so
it runs only on a recent Mac. Ghidra inspects it on any operating system,
because static analysis never executes the instructions. Every required answer
below is reachable without running it.

If you are on a Mac and want to run it, macOS quarantines files you downloaded,
so clear that flag first and make sure it is executable:

```bash
xattr -d com.apple.quarantine r17_reader
chmod +x r17_reader
./r17_reader note.r17
```

## Work period: about 22 minutes

Work in pairs. Record answers **and evidence** for each checkpoint. Suggested
pace: 5 minutes on Checkpoint 1, 7 on Checkpoint 2, 6 on Checkpoint 3, 4 on
Checkpoint 4.

### Checkpoint 1: Triage (~5 min)

1. Identify the executable format and architecture with `file`.
2. Compare the two data files with `hexdump -C` or `xxd`.
3. Record their common prefix, total size, and the bytes that differ.

### Checkpoint 2: File format (~7 min)

In Ghidra, find the code that opens the file and checks its contents. Searching
the strings for `R4178` or `Invalid checksum` and following a reference is a
faster way in than scanning the function list.

1. What are the first five bytes for?
2. Which byte gives the payload length?
3. Where is the checksum stored, and how is it calculated?
4. Why does `bad_checksum.r17` fail?

### Checkpoint 3: Decode (~6 min)

Find the loop that populates a **second** byte array. It is not the same loop
as the one that validates the file.

1. Which input byte becomes output position zero?
2. What operation changes each byte value?
3. Write a short script that recovers the text from `note.r17`.

### Checkpoint 4: Evidence (~4 min)

Submit a short explanation containing:

- The file layout, with byte offsets and lengths.
- The decoder rule, including the order of bytes.
- The recovered text and its character sum.
- A Ghidra location, screenshot, or pseudocode excerpt for each major claim.

Your own script can calculate the character sum on any platform. On a
compatible Mac the reader reports it independently, which is a second check on
the same answer.

**A recovered phrase without an explanation of the format and the loop does not
complete the task.** That is also the standard CTF 2 is marked against.

## Commands

```bash
file r17_reader note.r17 bad_checksum.r17
hexdump -C note.r17
hexdump -C bad_checksum.r17
strings -a r17_reader | less
```

Use only the supplied files and the environment authorized for the course.
