ARG OS_VERSION=latest
FROM fedora:$OS_VERSION

# Install systemd since pki runs as a systemd service
RUN true \
        && dnf update -y --refresh \
        && dnf install -y systemd openssh-server \
        && true

# Setup SSH Server with username and password.
# Authorize SSH connection with root account
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# change password root
RUN echo "root:docker"|chpasswd
