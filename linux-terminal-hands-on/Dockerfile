FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Tools the lab needs. Ubuntu's minimal image has none of the editors and no tree.
RUN apt-get update && apt-get install -y \
    python3 \
    tree \
    nano \
    vim \
    less \
    file \
    man-db \
    manpages \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged user. The lab never needs root.
RUN useradd -m -s /bin/bash student

# The project tree the students work on.
COPY --chown=student:student project /home/student/project

# The filters are not executable on purpose: Task 5 is where chmod is learned.
RUN chmod 644 /home/student/project/src/test/filters/exec/*.sh \
    && chmod 644 /home/student/project/src/main/code/*.py

# system_test.sh reports $USER, which is not set in a non-login shell.
ENV USER=student

USER student
WORKDIR /home/student/project

CMD ["/bin/bash"]
