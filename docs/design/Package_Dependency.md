# PKI Dependencies

This doc should give you an idea of the packages that Dogtag PKI project depends on during `Runtime` and `Buildtime`.

## `BuildRequires`

- git
- make
- cmake >= 2.8.9-1
- gcc-c++
- zip
- java-1.8.0-openjdk-devel
- redhat-rpm-config
- ldapjdk >= 4.20
- apache-commons-cli
- apache-commons-codec
- apache-commons-io
- apache-commons-lang
- jakarta-commons-httpclient
- glassfish-jaxb-api
- slf4j
- nspr-devel
- nss-devel >= 3.36.1
- openldap-devel
- pkgconfig
- policycoreutils
- python3-lxml
- python3-sphinx
- velocity
- xalan-j2
- xerces-j2
- jboss-annotations-1.2-api
- jboss-jaxrs-2.0-api
- jboss-logging
- resteasy-atom-provider >= 3.0.17-1
- resteasy-client >= 3.0.17-1
- resteasy-jaxb-provider >= 3.0.17-1
- resteasy-core >= 3.0.17-1
- resteasy-jackson2-provider >= 3.0.17-1
- python3-pylint
- python3-flake8 >= 2.5.4
- python3-pyflakes >= 1.2.3
- python3
- python3-devel
- python3-cryptography
- python3-lxml
- python3-nss
- python3-requests >= 2.6.0
- python3-six
- junit
- jpackage-utils >= 0:1.7.5-10
- jss >= 4.5.3
- tomcatjss >= 7.4.0
- systemd-units
- tomcat >= 1:9.0.7
- apr-devel
- apr-util-devel
- cyrus-sasl-devel
- httpd-devel >= 2.4.2
- pcre-devel
- systemd
- zlib
- zlib-devel
- go-md2man


## `Requires`

`dogtag-pki`
- nss >= 3.38.0

`pki-symkey`
- java-1.8.0-openjdk-headless
- jpackage-utils >= 0:1.7.5-10
- nss >= 3.38.0

`pki-base`
- nss >= 3.36.1

`python3-pki`
- python3-cryptography
- python3-lxml
- python3-nss
- python3-requests >= 2.6.0
- python3-six

`pki-base-java`
- java-1.8.0-openjdk-headless
- apache-commons-cli
- apache-commons-codec
- apache-commons-io
- apache-commons-lang
- apache-commons-logging
- jakarta-commons-httpclient
- glassfish-jaxb-api
- slf4j
- javassist
- jpackage-utils >= 0:1.7.5-10
- resteasy-atom-provider >= 3.0.17-1
- resteasy-client >= 3.0.17-1
- resteasy-jaxb-provider >= 3.0.17-1
- resteasy-core >= 3.0.17-1
- resteasy-jackson2-provider >= 3.0.17-1
- xalan-j2
- xerces-j2
- xml-commons-apis
- xml-commons-resolver

`pki-tools`

- openldap-clients
- nss-tools >= 3.36.1

`pki-server`

- hostname
- net-tools
- policycoreutils
- procps-ng
- openldap-clients
- openssl
- keyutils
- python3-lxml
- python3-libselinux
- python3-policycoreutils
- selinux-policy-targeted >= 3.13.1-159
- tomcat >= 1:9.0.7
- velocity