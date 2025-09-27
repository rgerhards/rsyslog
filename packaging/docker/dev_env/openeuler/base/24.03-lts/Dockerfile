# container for rsyslog development
# creates the build environment for openEuler
FROM    openeuler/openeuler:24.03-lts

# czmq is not packaged on openEuler 24.03 LTS, so the related modules are
# omitted from the build options below.

RUN     dnf -y update && \
        dnf -y install dnf-plugins-core && \
        (dnf config-manager --set-enabled everything || true) && \
        (dnf config-manager --set-enabled EPOL || true)

RUN     dnf -y install \
        apr-util-devel \
        autoconf \
        autoconf-archive \
        automake \
        bison \
        ca-certificates \
        clang \
        cmake \
        cyrus-sasl \
        cyrus-sasl-devel \
        diffutils \
        flex \
        gcc \
        gcc-c++ \
        gdb \
        git \
        gnutls-devel \
        hiredis \
        hiredis-devel \
        iproute \
        java-11-openjdk \
        java-11-openjdk-devel \
        krb5-devel \
        libbson-devel \
        libcap-ng-devel \
        libcurl-devel \
        libdbi-devel \
        libestr-devel \
        libfastjson-devel \
        libgcrypt-devel \
        lz4-devel \
        libmaxminddb-devel \
        mongo-c-driver-devel \
        libnet \
        libnet-devel \
        liblognorm-devel \
        libpcap-devel \
        librabbitmq-devel \
        librdkafka-devel \
        libstdc++ \
        libtool \
        libuuid-devel \
        libxml2-devel \
        libzstd-devel \
        logrotate \
        lsof \
        make \
        mariadb-connector-c-devel \
        mariadb-server \
        net-snmp-devel \
        net-tools \
        openssl-devel \
        patch \
        pkgconf-pkg-config \
        postgresql \
        postgresql-devel \
        python3 \
        python3-devel \
        python3-docutils \
        python3-pip \
        python3-setuptools \
        python3-sphinx \
        qpid-proton-c-devel \
        redhat-rpm-config \
        sudo \
        swig \
        systemd-devel \
        tcl-devel \
        valgrind \
        wget \
        which \
        zeromq-devel \
        zlib-devel \
        && dnf clean all

RUN     pip3 install --no-cache-dir pysnmp

RUN     mkdir /local_dep_cache

ENV     RSYSLOG_CONFIGURE_OPTIONS=" \
        --enable-compile-warning=error \
        --enable-elasticsearch \
        --disable-elasticsearch-tests \
        --enable-ffaup \
        --enable-gnutls \
        --enable-gssapi-krb5 \
        --enable-imbatchreport \
        --enable-imdiag \
        --enable-imfile \
        --enable-imhttp \
        --enable-imjournal \
        --enable-imkafka \
        --enable-impstats \
        --enable-impcap \
        --enable-imptcp \
        --enable-kafka-tests \
        --enable-libdbi \
        --enable-libgcrypt \
        --enable-libzstd \
        --enable-mmanon \
        --enable-mmcount \
        --enable-mmdblookup \
        --enable-mmfields \
        --enable-mmjsonparse \
        --enable-mmkubernetes \
        --enable-mmnormalize \
        --enable-mmpstrucdata \
        --enable-mmrm1stspace \
        --enable-mmsequence \
        --enable-mmsnmptrapd \
        --enable-mmutf8fix \
        --enable-mysql \
        --enable-omamqp1 \
        --enable-omhiredis \
        --enable-omhttpfs \
        --enable-omjournal \
        --enable-omkafka \
        --enable-ommongodb \
        --enable-omprog \
        --enable-omrabbitmq \
        --enable-omrelp-default-port=13515 \
        --enable-omruleset \
        --enable-omstdout \
        --enable-omtcl \
        --enable-omudpspoof \
        --enable-omuxsock \
        --enable-openssl \
        --enable-pgsql \
        --enable-pmciscoios \
        --enable-pmlastmsg \
        --enable-pmnormalize \
        --enable-pmnull \
        --enable-pmsnare \
        --enable-relp \
        --enable-snmp \
        --enable-snmp-tests \
        --enable-usertools \
        --enable-valgrind \
        --enable-testbench \
        "

RUN     groupadd -g 1000 rsyslog && \
        useradd -u 1000 -g rsyslog -m -s /bin/bash rsyslog && \
        echo "rsyslog ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

RUN     mkdir /rsyslog && \
        chown rsyslog:rsyslog /rsyslog

WORKDIR /rsyslog
USER    rsyslog
