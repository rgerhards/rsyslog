.. _tutorial-rosi-hetzner:

.. meta::
   :description: Deploy ROSI Collector on Hetzner Cloud for centralized log aggregation from multiple VPS instances.
   :keywords: rsyslog, ROSI, Hetzner Cloud, Loki, Grafana, centralized logging, tutorial

.. summary-start

Learn how to deploy ROSI Collector on Hetzner Cloud, configure client servers to forward logs and metrics, and use Grafana dashboards for visualization. Includes TLS/mTLS, firewall rules, and troubleshooting.
.. summary-end

Deploying ROSI Collector on Hetzner Cloud
=========================================

This tutorial guides you through deploying the ROSI (Rsyslog Operations Stack
Initiative) Collector on Hetzner Cloud for centralized log aggregation and
monitoring from multiple VPS instances.

.. note::
   For generic installation and client setup, see :doc:`../deployments/rosi_collector/index`
   and :doc:`../deployments/rosi_collector/client_setup`. This tutorial focuses on
   Hetzner Cloud-specific deployment.

Introduction
------------

Managing logs and metrics across multiple Hetzner Cloud VPS instances can be
challenging. Without centralized observability, you're left checking
individual servers, making it difficult to correlate events, troubleshoot
issues, or maintain a comprehensive view of your infrastructure.

ROSI Collector provides a production-ready, self-hosted solution for
centralized log aggregation and monitoring. Built on open-source
technologies—rsyslog, Loki, Grafana, and Prometheus—ROSI Collector offers a
lightweight alternative to resource-intensive stacks like ELK, while
maintaining full data sovereignty and privacy.

**Key Benefits:**

- **Self-hosted and privacy-focused**: Your logs stay in your infrastructure
- **Resource-efficient**: Lower memory and CPU footprint than ELK and similar stacks
- **Production-ready**: Includes pre-configured dashboards, alerting, and TLS support
- **Multi-server aggregation**: Collect logs and metrics from unlimited client servers
- **Cost-effective**: Runs efficiently on Hetzner Cloud CX22 or larger instances

Prerequisites
-------------

- A Hetzner Cloud Server (CX22 or larger recommended) running Ubuntu 24.04 LTS

  - For environments with more than 10 clients or high log verbosity (e.g. DEBUG
    level), consider CPX31 or CX32 for more stable Loki performance.
  - `SSH access <https://community.hetzner.com/tutorials/howto-ssh-key>`_
  - Root or sudo access
- Docker Engine 20.10+ and Docker Compose v2 (on a fresh server you can install
  them in one go using the ROSI script in the "Prepare fresh server" step; otherwise see
  `howto-docker-install <https://community.hetzner.com/tutorials/howto-docker-install>`_)
- Basic knowledge of Linux command line, Docker, and YAML
- (Optional) A domain name for TLS certificates via Let's Encrypt
- (Optional) Additional Hetzner Cloud VPS instances to act as clients

**Example terminology**

- Username: ``holu``
- Hostname: ``<your_host>``
- Domain: ``<example.com>``
- ROSI Collector server IP: ``<YOUR_COLLECTOR_PUBLIC_IP>``
- Client server IP: ``<YOUR_CLIENT_PUBLIC_IP>``

Architecture Overview
---------------------

ROSI Collector uses a centralized architecture where multiple client servers
forward logs and metrics to a single collector server. The collector
processes, stores, and visualizes this data through a web interface.

.. figure:: ../deployments/rosi_collector/rosi-architecture.svg
   :alt: ROSI Collector Architecture Overview
   :align: center
   :width: 100%

   ROSI Collector architecture - centralized logging with rsyslog, Loki, and Grafana

**Components:**

1. **rsyslog** - Receives syslog messages from clients via TCP port 10514 (or TLS on 6514)
2. **Loki** - Stores and indexes log data efficiently
3. **Grafana** - Provides web-based dashboards for log visualization and querying
4. **Prometheus** - Collects and stores metrics from node_exporter instances
5. **Traefik** - Reverse proxy with automatic TLS certificate management
6. **node_exporter** - Installed on each client (and the collector server) to expose system metrics

**Data Flow:**

1. Client servers forward syslog messages → ROSI Collector (TCP 10514/6514)
2. rsyslog receives logs → Forwards to Loki via HTTP
3. Loki stores logs → Grafana queries Loki for visualization
4. Prometheus scrapes node_exporter → Stores metrics → Grafana visualizes metrics
5. Users access Grafana via Traefik (HTTPS) → View dashboards and query logs

**Network Requirements:**

- **Inbound on collector**: TCP 80, 443 (Traefik), 9090 (Prometheus UI), 10514 (rsyslog plaintext), 6514 (rsyslog TLS, optional)
- **Outbound from clients**: TCP 10514/6514 to collector
- **Inbound on clients**: TCP 9100 (node_exporter, from collector)

Step 1 - Deploy ROSI Collector
------------------------------

In this step, we'll clone the ROSI Collector repository, initialize the
environment, and start the Docker Compose stack. See
:doc:`../deployments/rosi_collector/installation` for full installation details.

Clone Repository and Navigate to Directory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SSH into your Hetzner Cloud server and clone the rsyslog repository:

.. code-block:: bash

   ssh holu@<your_host>

Update your system packages:

.. code-block:: bash

   sudo apt update && sudo apt upgrade -y

Install required dependencies:

.. code-block:: bash

   sudo apt install -y git curl

Clone the rsyslog repository:

.. code-block:: bash

   git clone https://github.com/rsyslog/rsyslog.git
   cd rsyslog/deploy/docker-compose/rosi-collector

Prepare fresh server (first time only)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If this is a **new/fresh** Hetzner Cloud server and Docker is not yet
installed, run the prepare script **once** before initializing. It installs
Docker, configures the firewall, and applies optional hardening (sysctl,
fail2ban, logrotate, etc.):

.. code-block:: bash

   # From rosi-collector directory (after clone)
   sudo ./scripts/install-server.sh

The script will ask before installing each configuration file. For a fully
automated run:

.. code-block:: bash

   sudo NONINTERACTIVE=1 ./scripts/install-server.sh

.. warning::
   Only run this on fresh systems. Do not use it on servers you already
   maintain—it modifies system configuration and installs packages. If Docker
   is already installed (e.g. via `howto-docker-install
   <https://community.hetzner.com/tutorials/howto-docker-install>`_), skip this
   step and go to the next section.

Initialize Environment
~~~~~~~~~~~~~~~~~~~~~~

The initialization script (``init.sh``) will prompt you for configuration
values and set up the entire environment. Run it with sudo:

.. code-block:: bash

   sudo ./scripts/init.sh

**Interactive Prompts:**

The script will ask for the following information:

1. **Installation directory** (default: ``/opt/rosi-collector``)

   - Press Enter to accept the default, or specify a custom path
   - Your choice is saved for future runs (e.g. to
     ``~/.config/rsyslog/rosi-collector.conf`` or
     ``/etc/rsyslog/rosi-collector.conf``) and reused automatically on later runs

2. **TRAEFIK_DOMAIN** - Domain or IP address for accessing Grafana
   - If you have a domain: ``logs.example.com``
   - If using IP only: ``<YOUR_COLLECTOR_PUBLIC_IP>`` (will use self-signed certificate)
   - This is required

3. **TRAEFIK_EMAIL** - Email for Let's Encrypt certificate notifications
   - Example: ``admin@example.com``
   - Required for Let's Encrypt (not needed if using IP only)

4. **GRAFANA_ADMIN_PASSWORD** - Password for Grafana admin user
   - Press Enter to auto-generate a secure password (recommended)
   - Or enter your own password
   - The password will be shown at the end of setup and saved in ``.env``

5. **TLS Configuration** - Enable encrypted syslog on port 6514
   - Choose ``y`` for production environments (recommended)
   - Choose ``N`` for testing or if you'll use a VPN
   - If enabled, you'll configure TLS hostname and authentication mode

6. **Server syslog forwarding** - Forward the collector server's own logs
   - Choose ``Y`` to include the collector server's logs in Grafana (recommended)
   - Choose ``n`` if you only want client logs

When you run the script, output will look similar to:

.. code-block:: text

   Loaded configuration from: /root/.config/rsyslog/rosi-collector.conf
   Copying configuration files to /opt/rosi-collector...
   Rendering Grafana dashboards from templates (source)...
   Installing local Grafana dashboards...
   Downloading Grafana dashboards from grafana.com...
   Successfully downloaded dashboard 1860
   Successfully downloaded dashboard 14055
   Total dashboards installed: 13

   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     ROSI Collector Configuration
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   No .env file found. Please provide the following configuration:

   TRAEFIK_DOMAIN - The domain or IP address for accessing Grafana/Prometheus
   Examples: rosi.example.com, 192.168.1.100
   Enter domain or IP: logs.example.com

   TRAEFIK_EMAIL - Email for Let's Encrypt certificate notifications
   Enter email [admin@logs.example.com]:

   GRAFANA_ADMIN_PASSWORD - Leave empty to auto-generate a secure password
   Enter password (hidden) or press Enter to generate:

   Enable TLS for syslog? [y/N]: y

   TLS hostname [logs.example.com]:
   CA certificate validity in days [3650] (10 years):
   Server certificate validity in days [1825] (5 years):
   Client certificate validity in days [730] (2 years):

   Authentication mode:
     anon        - TLS encryption only (no client certificates)
     x509/certvalid - Require valid client certificates (mTLS)
     x509/name   - Require certificates + verify CN/SAN (strictest)
   Auth mode [anon]:

   Created .env file
   Configure server to forward its syslog to ROSI Collector? [Y/n]: y
   Configuration test passed
   Restarting rsyslog service...
   rsyslog service restarted successfully

   OK. ROSI Collector environment ready:
     /opt/rosi-collector
     Systemd service: rosi-collector-docker.service
     Monitor script: /usr/local/bin/rosi-monitor
     Prometheus target helper: /usr/local/bin/prometheus-target
     node_exporter: installed and running on this server
     TLS: enabled (port 6514, authmode: anon)

   IMPORTANT: Save your credentials!
     Grafana URL:    https://logs.example.com/
     Username:       admin
     Password:       (stored in /opt/rosi-collector/.env)

   Next steps:
     cd /opt/rosi-collector && docker compose up -d

**Important:** Save the Grafana admin password shown at the end of the script
output. You'll need it to log into Grafana.

**Non-interactive init:** You can run the script without prompts:

.. code-block:: bash

   sudo TRAEFIK_DOMAIN=logs.example.com TRAEFIK_EMAIL=admin@example.com ./scripts/init.sh

Optionally add ``SERVER_SYSLOG_FORWARDING=true`` to also enable forwarding the
collector server's own logs without prompting.

Start the Stack
~~~~~~~~~~~~~~~

Navigate to the installation directory and start the Docker Compose stack:

.. code-block:: bash

   cd /opt/rosi-collector
   docker compose up -d

The **first time** you run this, Docker will pull the required images
(Prometheus, Traefik, rsyslog-collector, nginx, Loki, Grafana), create the
data volumes, and then start the containers.

.. figure:: /_static/rosi-hetzner-docker-compose.png
   :alt: First-time stack start - docker compose up -d
   :align: center

   First-time stack start: docker compose up -d

Subsequent runs start the existing containers without re-pulling. Wait a few
moments for containers to initialize.

Verify Services are Running
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   docker compose ps

You should see all services in "Up" status. Alternatively:

.. code-block:: bash

   rosi-monitor status

Check Service Logs
~~~~~~~~~~~~~~~~~~

If any service fails to start:

.. code-block:: bash

   docker compose logs rsyslog
   docker compose logs grafana
   docker compose logs loki
   docker compose logs -f

**Common issues:** Port conflicts (80, 443, 9090, 10514, 6514), permission errors,
network issues. Check with ``docker network ls``.

Configure Firewall
~~~~~~~~~~~~~~~~~~

If you're using UFW (Uncomplicated Firewall):

.. code-block:: bash

   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw allow 9090/tcp
   sudo ufw allow 10514/tcp
   sudo ufw allow 6514/tcp
   sudo ufw status

.. note::
   If your Hetzner Cloud server uses the Hetzner Cloud Firewall (configured in
   the Cloud Console), you'll need to add rules there as well. The Hetzner
   Cloud Firewall operates at the network level and is separate from UFW.

Step 2 - Configure Client Servers
---------------------------------

Now that the ROSI Collector is running, configure client servers to forward
logs and metrics. See :doc:`../deployments/rosi_collector/client_setup` for
detailed client configuration.

Download Client Setup Script
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On each client server, download the rsyslog client setup script from your
ROSI Collector:

.. code-block:: bash

   wget https://<YOUR_COLLECTOR_PUBLIC_IP>/downloads/install-rsyslog-client.sh
   chmod +x install-rsyslog-client.sh

.. note::
   If using an IP address instead of a domain, you may need to accept a
   self-signed certificate warning. For ``wget``, add the ``--no-check-certificate`` flag.

The client script can optionally set up an rsyslog **impstats sidecar** (port
9898) for the "Syslog Health" dashboard. To skip it, run:
``sudo ./install-rsyslog-client.sh --no-sidecar``.

Run Client Setup Script
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   sudo ./install-rsyslog-client.sh

The script will prompt for ROSI Collector IP, port (default 10514), then
install rsyslog forwarding, create spool directory, and restart rsyslog.

Test Log Forwarding
~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   logger "Test message from $(hostname) at $(date)"

This message should appear in Grafana within a few seconds.

Install Node Exporter (Optional but Recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   wget https://<YOUR_COLLECTOR_PUBLIC_IP>/downloads/install-node-exporter.sh
   chmod +x install-node-exporter.sh
   sudo ./install-node-exporter.sh

Verify node_exporter is running:

.. code-block:: bash

   sudo systemctl status node_exporter
   curl http://localhost:9100/metrics | head -5

Add Client to Prometheus Targets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On the ROSI Collector server:

**Option A - node_exporter only (port 9100):**

.. code-block:: bash

   sudo prometheus-target add <YOUR_CLIENT_PUBLIC_IP>:9100 host=webserver role=web network=internal

**Option B - node_exporter and impstats sidecar (ports 9100 and 9898):**

.. code-block:: bash

   sudo prometheus-target add-client <YOUR_CLIENT_PUBLIC_IP> host=webserver role=web network=internal

**Label options:** ``host=<name>``, ``role=<value>``, ``env=<value>``,
``network=<value>``.

.. code-block:: bash

   sudo prometheus-target list

Configure Client Firewall
~~~~~~~~~~~~~~~~~~~~~~~~~

On each client, allow node_exporter (and impstats if used) from the collector:

.. code-block:: bash

   sudo ufw allow from <YOUR_COLLECTOR_PUBLIC_IP> to any port 9100 proto tcp
   sudo ufw allow from <YOUR_COLLECTOR_PUBLIC_IP> to any port 9898 proto tcp
   sudo ufw status | grep -E '9100|9898'

.. note::
   If using Hetzner Cloud Firewall, add rules allowing TCP ports 9100 (and
   9898 if using impstats) from the ROSI Collector server's IP.

Verify Client Connectivity
~~~~~~~~~~~~~~~~~~~~~~~~~~~

From the ROSI Collector server, verify you can reach the client's node_exporter:

.. code-block:: bash

   curl http://<YOUR_CLIENT_PUBLIC_IP>:9100/metrics | head -10

To verify the client can send logs to the collector, run from the client:
``telnet <YOUR_COLLECTOR_PUBLIC_IP> 10514``.

Step 3 - Access Grafana Dashboard
---------------------------------

Access Grafana
~~~~~~~~~~~~~~

Open your browser and navigate to:

- ``https://<YOUR_COLLECTOR_DOMAIN_OR_IP>`` (this is the value you set for ``TRAEFIK_DOMAIN``)

.. note::
   If using a self-signed certificate (IP address mode), your browser will
   show a security warning. Click "Advanced" and "Proceed to site" to continue.

Login to Grafana
~~~~~~~~~~~~~~~~

- **Username**: ``admin``
- **Password**: From the end of ``init.sh`` output, or:

.. code-block:: bash

   grep GRAFANA_ADMIN_PASSWORD /opt/rosi-collector/.env

Explore Pre-built Dashboards
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. figure:: /_static/rosi-hetzner-grafana.png
   :alt: Grafana Dashboards - Syslog Explorer and dashboard browser
   :align: center

   Grafana Dashboards - Syslog Explorer and dashboard browser

**Available Dashboards:**

1. **Syslog Explorer** - Search and browse logs from all clients
2. **Syslog Analysis** - Distribution analysis (severity, hosts, facilities)
3. **Syslog Health** - rsyslog impstats; requires impstats sidecar
4. **Host Metrics Overview** - System metrics from node_exporter
5. **Alerting Overview** - Active alerts and notification status

Query Logs in Grafana
~~~~~~~~~~~~~~~~~~~~~

In the Syslog Explorer dashboard: search bar, filter by host, time range.

**Example LogQL queries** (in Grafana Explore):

.. code-block:: text

   {host="webserver"}
   {host=~".+"} |= "error"
   {facility="auth"}
   {host=~".+"} |= "failed"

View Metrics Dashboards
~~~~~~~~~~~~~~~~~~~~~~~

Open "Host Metrics Overview" for CPU, memory, disk I/O, network, load average.

Step 4 - Advanced Configuration
-------------------------------

Enable TLS/mTLS for Syslog
~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Edit ``.env``: ``SYSLOG_TLS_ENABLED=true``, ``SYSLOG_TLS_HOSTNAME=logs.example.com``, ``SYSLOG_TLS_AUTHMODE=anon``
2. Re-run ``sudo ./scripts/init.sh`` from the cloned rosi-collector directory
3. Restart: ``cd /opt/rosi-collector && docker compose restart rsyslog``

**Authentication Modes:** ``anon`` (server-only), ``x509/certvalid`` (mTLS),
``x509/name`` (mTLS with name validation).

**Generate client certificates:**

.. code-block:: bash

   rosi-generate-client-cert --download client-hostname

Configure Log Retention
~~~~~~~~~~~~~~~~~~~~~~~

Edit ``/opt/rosi-collector/loki-config.yml``:

.. code-block:: yaml

   limits_config:
     retention_period: 720h  # 30 days (default)
     # Change to 168h for 7 days, or 2160h for 90 days

Restart Loki: ``docker compose restart loki``

Add More Clients
~~~~~~~~~~~~~~~~

Repeat Step 2 for each new server. Quick checklist:

- [ ] Download and run ``install-rsyslog-client.sh`` on client
- [ ] (Optional) Install node_exporter on client
- [ ] Add client to Prometheus: ``sudo prometheus-target add-client <IP> host=<name> role=<role> network=<network>``
- [ ] Configure client firewall for 9100 (and 9898 if impstats)
- [ ] Verify connectivity and test log forwarding

Configure Hetzner Cloud Firewall
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**ROSI Collector Server:** Inbound TCP 80, 443, 9090, 10514, 6514

**Client Servers:** Inbound TCP 9100 from collector IP; outbound TCP 10514, 6514 to collector

In Hetzner Cloud Console → Firewalls:

1. **Rule for ROSI Collector:** Direction Inbound, Port 80, 443, 9090, 10514, 6514
2. **Rule for Clients:** Direction Inbound, Port 9100, Source: collector IP

Monitor Stack Health
~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   rosi-monitor status
   rosi-monitor logs
   rosi-monitor health
   rosi-monitor debug

See :doc:`../deployments/rosi_collector/troubleshooting` for the full list.

Step 5 - Troubleshooting
------------------------

Logs Not Appearing in Grafana
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Check rsyslog on collector: ``docker compose logs rsyslog | tail -50``
2. Verify Loki: ``curl http://localhost:3100/ready`` (should return "Ready")
3. Test client connectivity (from a client machine): ``telnet <YOUR_COLLECTOR_PUBLIC_IP> 10514``
4. On client: ``sudo rsyslogd -N1``, ``sudo systemctl status rsyslog``

**rsyslog omfwd errors:** Remove any explicit ``module(load="omfwd")``; the
omfwd action is built-in.

Container Won't Start
~~~~~~~~~~~~~~~~~~~~~

1. Check logs: ``docker compose logs <service-name>``
2. Verify disk space: ``df -h`` (10GB+ free recommended)
3. Check Docker: ``systemctl status docker``
4. Verify ports: ``sudo netstat -tlnp | grep -E ':(80|443|10514|6514|3000|3100|9090)'``

Prometheus Can't Scrape node_exporter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Server target down:** The node_exporter must bind to Docker bridge gateway.
Check ``grep listen-address /etc/systemd/system/node_exporter.service`` and
``rosi-monitor status`` for network info.

**Client targets down:**

1. On client: ``sudo systemctl status node_exporter``, ``curl http://localhost:9100/metrics``
2. Verify firewall: ``sudo ufw status | grep 9100``
3. From collector: ``curl http://<YOUR_CLIENT_PUBLIC_IP>:9100/metrics``
4. Prometheus UI: ``https://logs.example.com:9090`` → Status → Targets

High Memory Usage
~~~~~~~~~~~~~~~~~

1. Check: ``free -h``, ``docker stats``
2. To reduce Loki's memory usage, edit ``/opt/rosi-collector/loki-config.yml`` and
   add the following under ``limits_config``:

   .. code-block:: yaml

      ingestion_rate_mb: 10
      ingestion_burst_size_mb: 20

3. Reduce retention (see the "Configure Log Retention" section)
4. Upgrade to CX32 or larger for high load

TLS Certificate Issues
~~~~~~~~~~~~~~~~~~~~~~

1. Verify certs: ``ls -la /opt/rosi-collector/certs/`` (ca.pem, server-cert.pem, server-key.pem)
2. Check validity: ``openssl x509 -in /opt/rosi-collector/certs/server-cert.pem -text -noout | grep -A 2 Validity``
3. Regenerate: ``sudo rm -rf /opt/rosi-collector/certs/`` then ``sudo ./scripts/init.sh``

Conclusion
----------

You've successfully deployed ROSI Collector on Hetzner Cloud. Your
observability stack now provides:

- **Centralized log aggregation** from all Hetzner Cloud VPS instances
- **System metrics collection** via Prometheus and node_exporter
- **Web-based visualization** through Grafana dashboards
- **Production-ready features** including TLS support, alerting, and log retention

**Next Steps:**

- Explore additional Grafana dashboards
- Configure alerting rules in Prometheus
- Set up TLS/mTLS for production
- Add more client servers

**Additional Resources:**

- :doc:`../deployments/rosi_collector/index` - ROSI Collector overview
- :doc:`../deployments/rosi_collector/installation` - Full installation guide
- :doc:`../deployments/rosi_collector/client_setup` - Client setup details
- :doc:`../deployments/rosi_collector/grafana_dashboards` - Grafana dashboards
- :doc:`../deployments/rosi_collector/troubleshooting` - Troubleshooting guide
- `ROSI Collector source <https://github.com/rsyslog/rsyslog/tree/main/deploy/docker-compose/rosi-collector>`_
- `Grafana Documentation <https://grafana.com/docs/grafana/latest/>`_
- `Loki Documentation <https://grafana.com/docs/loki/latest/>`_
- `Prometheus Documentation <https://prometheus.io/docs/>`_

**Maintenance Tips:**

- Regularly check ``rosi-monitor status``
- Monitor disk usage in ``/opt/rosi-collector``
- Review and rotate log retention
- Keep Docker and container images updated
- Backup the ``.env`` file and configuration directory

.. rubric:: Attribution

Based on the `Hetzner Community tutorial
<https://github.com/alorbach/community-content/commit/6f96122dd2acfcd41bb8be2071c8d42b7f32303f>`_
by alorbach (MIT licensed).
