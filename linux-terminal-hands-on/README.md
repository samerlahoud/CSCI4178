# H01, Introduction to the Linux Terminal

Student material for the week 2 hands-on session of **CSCI 4178, Cyber Security and Defense**.

## Quick start

```bash
git clone https://github.com/samerlahoud/CSCI4178.git
cd CSCI4178/linux-terminal-hands-on
docker build -t linux-terminal-lab .
docker run --rm -it --hostname h01 linux-terminal-lab
```

You land as `student` in `/home/student/project`. Open [`linux-terminal-lab.md`](linux-terminal-lab.md) and start at Part 1.

Without Docker, on macOS or Linux, `cd project` and start at Part 1. Section 0.3 of the handout lists the two differences to expect.

## Contents

| Path | What it is |
|------|------------|
| `linux-terminal-lab.md` | The handout. This is what students work from. |
| `Dockerfile` | Ubuntu 24.04 with `python3`, `tree`, `nano`, `vim`, `less`, `file`, and `man`. |
| `project/` | The test harness the lab works on. Copied into the image at `/home/student/project`. |

Solutions are not published here.

## A note on the project tree

The scripts under `project/` are deliberately undocumented and several of them are decoys. That is the exercise. `src/main/code/io_tester.py` is the only file that does real work, and the `Path Hash` it prints is the checkpoint for the whole session.

The shell scripts and Python files ship without the execute bit on purpose. Task 4 is where that gets fixed.
