# H01 - Introduction to the Linux Terminal

**CSCI 4178 Cyber Security and Defense, Fall 2026**
Hands-on session, week 2. Duration: 80 minutes.

---

## Learning goals

By the end of this session you will be able to:

- Navigate a filesystem and inspect its contents without a graphical file manager.
- Locate a file by name with `find` and by content with `grep`.
- Create, move, and edit files from the shell.
- Redirect and pipe the output of one program into another.
- Make a script executable and run it.
- Explain why an attacker who reaches a shell, or reaches a program that calls one, has reached the whole system.

No prior shell experience is assumed.

---

## Why this session exists

Almost everything else in this course happens in a terminal. Scanners, proxies, debuggers, disassemblers, exploit scripts, and the machines you will attack in the labs all live behind a command line. A target you compromise gives you a shell, not a desktop.

There is a second reason, which is the point of Part 3. Software calls the shell constantly, to compare two files, to resize an image, to send a mail. Every one of those calls is a place where attacker-controlled text can become an attacker-controlled command. You cannot see that risk until you know what the shell does with the text it is given.

---

## Ground rules

- **Do not use the mouse.** Not for navigation, not for selecting text, not for opening files. This is the whole point of the session.
- **Do not paste a command you do not understand.** Type it. If you do not know what a flag does, run `man <command>` or `<command> --help`.
- Work through the tasks in order. Each one depends on the state left by the previous one.
- Getting the wrong result is normal. Read the error message before asking; it usually names the problem.

---

## 0. Setup

### 0.1 Get the lab

Clone the repository:

```bash
git clone https://github.com/samerlahoud/CSCI4178.git
cd CSCI4178/linux-terminal-hands-on
```

If you already cloned `CSCI4178` for an earlier session, `git pull` instead.

### 0.2 Build and run the container (recommended)

The container gives everyone the same Linux, the same tools, and the same answers. Use it if you are on Windows, and use it on macOS unless you have a reason not to.

```bash
docker build -t linux-terminal-lab .
docker run --rm -it --hostname h01 linux-terminal-lab
```

You land as user `student` in `/home/student/project`. Nothing in the container needs `sudo`.

`--rm` deletes the container when you exit, so your work is not saved. That is deliberate for a 60-minute session. If you want to keep it, drop `--rm` and restart later with `docker start -ai <container-name>`.

### 0.3 Without Docker (macOS or Linux only)

The lab works on a native macOS or Linux terminal. Change into the `project` directory and start at Part 1:

```bash
cd project
```

Two differences to expect:

- `tree` is not installed by default on macOS. Use `find .` instead, or `brew install tree`.
- `uname -v` prints your own kernel, so the `system:` and `kernel:` lines in your results will not match anyone else's. The **Path Hash** will still match, because it is computed from the path relative to `project`, not from the absolute path.

### 0.4 Check that you are in the right place

```bash
pwd
ls
```

You should see `README.txt`, `LICENSE.txt`, `docs`, and `src`.

---

## Part 1. Orientation (10 minutes)

You have inherited a test harness from a developer who left no documentation worth the name. Your job is to work out what it does and make it run.

Start by reading what little documentation there is:

```bash
cat README.txt
cat docs/notes.txt
```

Now look around. The `project` directory is the root of everything you will touch.

```bash
pwd                 # where am I
ls                  # what is here
ls -l               # the same, with size, owner, and permissions
ls -la              # the same, including hidden files
tree                # the whole tree at once
cd src/main/code    # go somewhere
cd ..               # go up one level
cd -                # go back to where you were
cd                  # go home
```

**Questions to answer before moving on.** Write the answers down; you will need them.

1. How many directories are under `src`? Two of them look empty to `ls` but are not. Which two, and what is in them?
2. Which directory holds Python files? Which holds shell scripts?
3. Run `ls -l` on `src/main/code`. Does any file have execute permission?

> **Keyboard survival.** Press `Tab` to complete a path instead of typing it. Press it twice to list the candidates. Press the up arrow to recall the previous command. `Ctrl+C` cancels a running command. `Ctrl+D` ends input. `Ctrl+L` clears the screen.

---

## Part 2. The eight tasks (45 minutes)

Do them in order. After each task there is a **Checkpoint** describing what you should see. If your checkpoint does not match, fix it before continuing, because everything downstream depends on it.

### Task 1. Find two files

Looking for files by hand does not scale. Two commands do it for you: `find` searches by name, `grep` searches inside files.

1. Locate the file named `system_test.sh`. Do not guess the path, search for it.
2. Locate the **one Python script that contains the word `Hash` inside the file**, not in its filename. There are four Python files, and the one named after hashing is not the one you want.

*Commands: `find`, `grep`.*

**Hints.** `find . -name "<pattern>"` searches the current directory downwards. `grep -r "<text>" .` searches recursively inside files. `grep -rn` adds line numbers, `grep -rl` lists only the filenames. To restrict the search to Python files, add `--include="*.py"`.

**Checkpoint.** You have two paths, one ending in `.sh` and one ending in `.py`. Note that `grep -ri hash .` returns a third file that is not a Python script at all. Case matters, and so does where you look.

### Task 2. Move the script

Move `system_test.sh` into the directory where you found the Python script from Task 1.

*Command: `mv`.*

**Hints.** `mv <source> <destination>`. If the destination is a directory, the file keeps its name. You can run this from anywhere if you give both paths in full.

**Checkpoint.** `ls src/main/code` lists `system_test.sh` alongside the Python files, and `src/test/filters/exec` no longer contains it.

### Task 3. Create the results file

Change into the directory holding both files. Create a file called `results.txt` and put **your full name** on the first line, nothing else.

*Commands: `cd`, `touch`, `nano` or `vim`.*

**Hints.** `touch results.txt` creates an empty file. `nano results.txt` opens an editor; write your name, then `Ctrl+O` `Enter` to save and `Ctrl+X` to quit. If you prefer not to open an editor, `echo "Your Name" > results.txt` does the same thing in one step, and you will understand why by the end of Task 6.

**Checkpoint.** `cat results.txt` prints your name and nothing else. `wc -l results.txt` reports `1`.

### Task 4. Make the script runnable

Try to run the shell script the direct way:

```bash
./system_test.sh
```

It fails. Read the error.

1. Run `ls -l system_test.sh` and look at the permission string on the left.
2. Give the file execute permission with `chmod +x system_test.sh`.
3. Run `./system_test.sh` again.

*Commands: `ls -l`, `chmod`.*

**Hints.** `ls -l` shows permissions as `rwx` triples for owner, group, and everyone else. A `-` means the permission is absent. `chmod +x <file>` adds execute for everybody.

**Checkpoint.** `ls -l system_test.sh` now shows `x` in the permission string, and running `./system_test.sh` prints four lines: `full path`, `user`, `system`, `kernel`.

> **Why `./`?** The shell only searches the directories listed in `$PATH` for a command, and the current directory is not one of them. `./system_test.sh` says "the file named `system_test.sh` in this directory". Run `echo $PATH` to see the list. The fact that `.` is *not* on it is a security decision: if it were, dropping a file named `ls` into a directory would hijack anyone who typed `ls` there.
>
> There is a second way to run the script that does not need execute permission at all: `sh system_test.sh`. Here you are running `sh` and handing it the script as data. Permission to execute a file and permission to read it are not the same thing, and this distinction comes back in H02.

### Task 5. Pipe one program into another

`system_test.sh` prints information. The Python script from Task 1 expects that information on its standard input. Connect them so that the output of the script becomes the input of the Python program.

*Commands: `sh` or `./`, `python3`, `|`.*

**Hints.** `command1 | command2` sends the standard output of the first command to the standard input of the second. Nothing is written to disk. Use `python3`, not `python`, which may not exist.

**Checkpoint.** You see six lines on screen, ending with a line that starts `Path Hash: `. Do not worry yet about whether the hash is correct.

### Task 6. Redirect the output into the file

Run exactly the same pipeline, but send the result to the end of `results.txt` instead of the screen, without destroying the name you wrote in Task 3.

*Operator: `>>`.*

**Hints.** `>` writes to a file and **replaces** whatever was there. `>>` writes to a file and **appends**. This is the single most expensive keystroke difference in this session. If you use `>` by mistake, redo Task 3.

**Checkpoint.** Nothing is printed on screen. The command returns immediately and silently.

### Task 7. Check your work

Display the file and compare the last line with the expected value.

```bash
cat results.txt
```

The `Path Hash` line must read:

```
6c7f4c5efbacdde8e89cb85ed1f79506535fa1c064ac97aac2aa6f8fd806e162
```

*Command: `cat`.*

**If it does not match**, the Python script did not see the path it expected. The usual cause is running the pipeline from the wrong directory. The hash is computed from the project-relative path of the directory you ran in, so it only comes out right from `project/src/main/code`. Check with `pwd`, then redo Tasks 3, 5, and 6.

**Checkpoint.** `results.txt` contains your name followed by six lines of output, and the hash matches.

### Task 8. Measure the file

Count the lines, words, and characters in `results.txt`.

*Command: `wc`.*

**Hints.** `wc <file>` prints lines, words, and characters in that order. `wc -l`, `wc -w`, and `wc -c` print one each.

**Checkpoint.** You have **7 lines**. The character count will differ from your neighbour's, because the `full path` and `kernel` lines describe your machine.

---

## Part 3. Why security cares (10 minutes)

Everything so far was one person typing commands. Now consider a program that builds a command out of text somebody else typed.

Still inside `src/main/code`, create a small tool that compares two files. Open an editor:

```bash
nano compare.py
```

and type this in:

```python
import os

file1 = input("What is file 1? ")
file2 = input("What is file 2? ")
os.system(f"diff {file1} {file2}")
```

Save with `Ctrl+O` `Enter`, quit with `Ctrl+X`.

Now give it something to compare, and something it was never meant to reveal:

```bash
echo "version one" > report_v1.txt
echo "version two" > report_v2.txt
echo "the password is hunter2" > secret_file.txt
```

Run it normally first:

```bash
python3 compare.py
```

Answer `report_v1.txt` and `report_v2.txt`. It behaves exactly as intended.

Run it again. Answer `report_v1.txt` for the first file. For the second, answer:

```
meh; cat secret_file.txt
```

**What to observe.** The program asked for a filename and got a filename plus a second command. `os.system` does not compare strings to a list of valid filenames; it hands the whole string to a shell, and `;` is how a shell separates one command from the next. The developer wrote one command. The user ran two.

**Questions.**

1. The second command ran with exactly the permissions of the program that called it. In this container that is `student`. What would it have been on a web server running as `root`?
2. `;` is not the only separator. What would `| `, `&&`, and backticks do in the same position?
3. The program never intended to read `secret_file.txt`. Name three files on a real server that an attacker would try to read this way.

This is **command injection**, and it is a specific case of the pattern that runs through the whole course: data supplied by a user crosses a boundary and is interpreted as instructions. You will see the same shape in SQL injection next week and in cross-site scripting the week after.

---

## Self-check

You are done when all of these are true:

| # | Check | Command |
|---|-------|---------|
| 1 | `system_test.sh` sits in `src/main/code` | `ls src/main/code` |
| 2 | `system_test.sh` is executable | `ls -l src/main/code/system_test.sh` |
| 3 | `results.txt` starts with your name | `head -1 results.txt` |
| 4 | The hash matches the value in Task 7 | `tail -1 results.txt` |
| 5 | The file has 7 lines | `wc -l results.txt` |

Nothing is submitted. This session is not graded.

---

## Appendix A. Command cheat sheet

**Where am I, what is here**

```bash
pwd                       # print working directory
ls                        # list files
ls -l                     # long format: permissions, owner, size, date
ls -la                    # include hidden files (names starting with .)
tree                      # recursive view of the directory
cd <dir>                  # change directory
cd ..                     # up one level
cd -                      # back to the previous directory
```

**Reading files**

```bash
cat <file>                # print the whole file
less <file>               # page through it, q to quit
head -n 5 <file>          # first 5 lines
tail -n 5 <file>          # last 5 lines
wc <file>                 # lines, words, characters
file <file>               # what kind of file is this
```

**Changing things**

```bash
touch <file>              # create an empty file
mkdir <dir>               # create a directory
cp <src> <dst>            # copy
mv <src> <dst>            # move or rename
rm <file>                 # delete, with no undo and no trash
rmdir <dir>               # delete an empty directory
chmod +x <file>           # make executable
nano <file>               # edit: Ctrl+O saves, Ctrl+X quits
```

**Searching**

```bash
find . -name "*.sh"              # by filename, recursively
grep "text" <file>               # inside one file
grep -rn "text" .                # recursively, with line numbers
grep -rl "text" .                # list matching filenames only
grep -ri "text" .                # ignore case
grep -r "text" --include="*.py" . # restrict to Python files
```

**Redirection and pipes**

```bash
command > file            # stdout to file, overwriting it
command >> file           # stdout appended to file
command < file            # file as stdin
command 2> file           # stderr to file
command1 | command2       # stdout of the first as stdin of the second
```

**Processes**

```bash
command &                 # run in the background
jobs                      # list background jobs of this shell
fg %1                     # bring job 1 to the foreground
ps                        # list processes
kill <pid>                # signal a process to stop
```

**Getting help**

```bash
man <command>             # the manual, q to quit
<command> --help          # the short version
```

## Appendix B. If something goes wrong

| Symptom | Cause | Fix |
|---------|-------|-----|
| `command not found` | Typo, or the tool is not installed | Check the spelling. In the container, everything this lab needs is installed. |
| `Permission denied` running `./script.sh` | The file has no execute bit | `chmod +x script.sh`, or run it as `sh script.sh` |
| `No such file or directory` | You are not where you think | `pwd`, then `ls` |
| `python: command not found` | Ubuntu ships `python3` only | Use `python3` |
| The hash does not match | The pipeline ran from the wrong directory | `cd` to `project/src/main/code` and redo Tasks 3, 5, 6 |
| `results.txt` lost your name | `>` was used instead of `>>` | Redo Task 3, then Task 6 with `>>` |
| The terminal stopped responding to input | A command is still running | `Ctrl+C` to cancel, `Ctrl+D` to end input |
| Stuck inside `vim` | vim is modal | `Esc` then `:q!` then `Enter` to quit without saving |

## Appendix C. Going further

- `man bash` is the complete reference. It is long. `man` it once, so you know it is there.
- Learn `Ctrl+R`. It searches your command history backwards and will save you more typing than anything else in this handout.
- Everything you typed today is recorded in your shell history. Run `history`. Consider what that file tells an attacker who reads it, and what it tells an investigator who reads it after an incident.
