FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ubuntu:24.04 breaks `man` in two separate ways, and both have to be undone or
# the handout's "run man <command>" advice fails in front of the room.
#
#   1. dpkg is configured to discard man pages on install, so the pages are
#      simply absent. Removing the exclusion list and reinstalling the packages
#      that own the commands this lab teaches brings them back.
#   2. the real man binary is diverted to /usr/bin/man.REAL and replaced by a
#      stub that only prints "this system has been minimized". Installing
#      man-db does not undo that, because the diversion is local. It has to be
#      removed explicitly.
#
# `unminimize` fixes both and costs several hundred megabytes more, which
# matters in a room building this over shared wifi.
RUN rm -f /etc/dpkg/dpkg.cfg.d/excludes \
    && rm -f /usr/bin/man \
    && dpkg-divert --quiet --remove --rename /usr/bin/man

RUN apt-get update && apt-get install -y \
    man-db \
    manpages \
    python3 \
    tree \
    nano \
    vim \
    less \
    file \
    procps \
    && apt-get install -y --reinstall \
    coreutils \
    findutils \
    grep \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged user. The lab never needs root.
RUN useradd -m -s /bin/bash student

# The project tree the students work on.
COPY --chown=student:student project /home/student/project

# The filters are not executable on purpose: Task 4 is where chmod is learned.
RUN chmod 644 /home/student/project/src/test/filters/exec/*.sh \
    && chmod 644 /home/student/project/src/main/code/*.py

# system_test.sh reports $USER, which is not set in a non-login shell.
ENV USER=student

USER student
WORKDIR /home/student/project

CMD ["/bin/bash"]
