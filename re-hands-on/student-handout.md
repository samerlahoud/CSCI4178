# Reverse engineering workshop: the scrambler

## Situation

A small development team wrote `scrambler` to hide internal notes before
committing them to a shared repository. The tool reads a line from
`message.txt`, transforms it, and writes the result to `message.scr`.

You do **not** have `message.txt`. You have the compiled program and one
scrambled file. The source and any specification are unavailable.

Your task is to work out what `scrambler` does to a message, then recover the
original line from `message.scr`.

The original line is a single line of ASCII letters, digits and underscores.
It contains no spaces and no other punctuation.

## Provided files

- `scrambler`: the compiled program
- `message.scr`: the scrambled output

## Before you start

**Ghidra** is the disassembler and decompiler for this workshop. It is free,
runs on macOS, Windows and Linux, and needs a JDK 21 or later.

- Download: <https://ghidra-sre.org/>
- If you do not have it working, start with Checkpoint 1 anyway. It needs only
  `hexdump`. Ask for the pseudocode excerpt and you can still do Checkpoints
  2 and 3 from real code.

**Running the program is optional.** It is a macOS Apple Silicon executable, so
it runs only on a recent Mac. Ghidra inspects it on any operating system,
because static analysis never executes the instructions. Every required answer
below is reachable without running it.

If you are on a Mac and want to run it, macOS quarantines files you downloaded,
so clear that flag first and make sure it is executable:

```bash
xattr -d com.apple.quarantine scrambler
chmod +x scrambler
```

Note what running it actually gives you. `scrambler` only scrambles: it reads
`message.txt` and overwrites `message.scr`. It will not undo anything. **Copy
`message.scr` somewhere safe before you run the program**, or you will destroy
the file you were given.

Used deliberately, though, the program is an oracle: put a line you choose into
`message.txt`, run it, and compare the output with your input. That is a
legitimate way to establish the transformation, and it is dynamic analysis in
the sense of slide 8. It still does not excuse you from locating the code.

## Work period: about 22 minutes

Work in pairs. Record answers **and evidence** for each checkpoint. Suggested
pace: 5 minutes on Checkpoint 1, 7 on Checkpoint 2, 6 on Checkpoint 3, 4 on
Checkpoint 4.

### Checkpoint 1: Triage (~5 min)

1. Identify the executable format and architecture with `file`.
2. Look at the scrambled file with `hexdump -C message.scr`.
3. Record its length, which bytes are printable and which are not, and any
   byte value that repeats in a suggestive position.
4. Run `strings -a scrambler`. Two filenames and one error message come back.

### Checkpoint 2: Find the transformation (~7 min)

In Ghidra, find the code that runs between reading the file and writing it.
Searching the strings for `message.txt` or `message.scr` and following a
reference is a faster way in than scanning the function list. The imports
`fopen`, `fgets`, `strcspn` and `fwrite` divide `main` into a reading part, a
transforming part and a writing part.

1. How many loops sit between the read and the write?
2. What is the loop bound in each one, and why are the two bounds different?
3. Which loop moves bytes, and which loop changes byte values?

### Checkpoint 3: Name the two operations (~6 min)

Describe the transformation precisely, using the two axes from slide 13.

1. **Position:** where does the byte at index `i` end up?
2. **Value:** what arithmetic or bitwise operation is applied, and with what
   operand?
3. Is the operand a fixed constant, or does it depend on `i`?

### Checkpoint 4: Invert and verify (~4 min)

1. Write a short script that reads `message.scr`, applies the inverse of what
   you found, and prints the recovered line.
2. Check it against the stated character set: letters, digits and underscores
   only. A result with stray punctuation means one of the two axes is wrong.
3. **Round trip.** Apply the forward transformation to your recovered line and
   show that you get `message.scr` back, byte for byte. That is the check that
   makes the answer a result rather than a guess, and it works on any platform.

Submit a short explanation containing the two operations, their location in the
code, the recovered line, and the round-trip check.

**A recovered line without an explanation of both operations does not complete
the task.** That is also the standard CTF 2 is marked against.

## Commands

```bash
file scrambler message.scr
hexdump -C message.scr
strings -a scrambler
cp message.scr message.scr.backup
```

Use only the supplied files and the environment authorized for the course.
