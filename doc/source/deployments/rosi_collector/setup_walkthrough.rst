.. _rosi-collector-setup-walkthrough:

ROSI Collector Setup Walkthrough
================================

.. meta::
   :description: End-to-end ROSI Collector walkthrough for standing up a collector, connecting a client, and validating logs and metrics.
   :keywords: rsyslog, ROSI Collector, setup, walkthrough, Grafana, Loki, Prometheus, client onboarding

.. summary-start

This walkthrough takes you from a fresh collector host to a working ROSI
deployment with one enrolled client, visible logs, and basic metrics.

.. summary-end

Use this page when you want the shortest practical path to a working ROSI
Collector environment. It connects the detailed guides into one operator flow:
prepare the collector host, initialize the stack, enroll one client, and check
that logs and metrics are visible in Grafana.

If you need deeper explanation for any step, jump to :doc:`installation`,
:doc:`client_setup`, :doc:`grafana_dashboards`, or :doc:`troubleshooting`.

Outcome
-------

At the end of this walkthrough you should have:

- A ROSI Collector host running Docker Compose services
- One client forwarding logs to the collector
- Optional host metrics visible through Prometheus and Grafana
- A known-good validation path for future client onboarding

Before You Begin
----------------

Prepare one Linux host for the collector and one additional Linux host to act
as a client. The deployment scripts are tested on Ubuntu 24.04 LTS; nearby
Debian-family distributions are the lowest-risk choice. Use a DNS name if you
want browser-trusted HTTPS and simpler TLS setup for syslog clients. IP-only
deployments work, but they usually rely on a self-signed certificate for the
web interface.

Open the required network paths before you start:

- Collector inbound: ``80/tcp``, ``443/tcp``, ``10514/tcp``
- Collector inbound when syslog TLS is enabled: ``6514/tcp``
- Client inbound for metrics: ``9100/tcp``
- Client inbound for impstats sidecar, if used: ``9898/tcp``

If your environment uses a cloud firewall or security group in addition to the
host firewall, configure both layers. Avoid provider-specific assumptions and
keep the allowed source ranges as narrow as your environment permits.

Step 1: Prepare the Collector Host
----------------------------------

Clone the rsyslog repository and move to the ROSI Collector deployment:

.. code-block:: bash

   git clone https://github.com/rsyslog/rsyslog.git
   cd rsyslog/deploy/docker-compose/rosi-collector

On a fresh host, install the baseline dependencies first:

.. code-block:: bash

   sudo apt update
   sudo apt install -y git curl

If Docker is not installed yet and this is a new machine, run the bootstrap
script once:

.. code-block:: bash

   sudo ./scripts/install-server.sh

That script can install Docker and apply optional system changes. Use it only
on hosts where those changes are expected. On an existing server, install
Docker with your normal platform process and skip the bootstrap script.

Next, initialize the deployment:

.. code-block:: bash

   sudo TRAEFIK_DOMAIN=logs.example.com \
        TRAEFIK_EMAIL=admin@example.com \
        ./scripts/init.sh

The script copies the stack into the install directory, generates ``.env``,
installs helper tools such as ``rosi-monitor`` and ``prometheus-target``, and
can optionally configure the collector host to forward its own logs. Record the
Grafana admin password shown at the end of the run.

The most important prompts during initialization are:

- Install directory, usually ``/opt/rosi-collector``
- ``TRAEFIK_DOMAIN`` for the public hostname or IP
- ``TRAEFIK_EMAIL`` for Let's Encrypt notifications
- Grafana admin password, either generated or supplied
- Syslog TLS enablement and auth mode
- Whether the collector should forward its own local logs

If you need to automate the setup, rerun the script with environment variables
instead of answering interactively:

.. code-block:: bash

   sudo TRAEFIK_DOMAIN=logs.example.com \
        TRAEFIK_EMAIL=admin@example.com \
        SERVER_SYSLOG_FORWARDING=true \
        ./scripts/init.sh

Step 2: Start and Verify the Stack
----------------------------------

Move to the generated install directory and start the services:

.. code-block:: bash

   cd /opt/rosi-collector
   sudo docker compose up -d

Confirm that the core services are healthy:

.. code-block:: bash

   sudo docker compose ps
   sudo rosi-monitor status
   curl http://localhost:3100/ready

You are looking for a stable state where rsyslog, Loki, Grafana, Prometheus,
and Traefik are all up, and Loki returns ``ready``. If a service does not come
up cleanly, stop here and use :doc:`troubleshooting` before onboarding clients.

On the first run, Docker also has to pull images and create the persistent
volumes, so ``docker compose up -d`` takes noticeably longer than later starts.

.. figure:: /_static/rosi-setup-docker-compose.png
   :alt: First ROSI Collector start with docker compose up -d
   :align: center

   First stack start after initialization.

If any service fails, the most useful immediate checks are:

.. code-block:: bash

   sudo docker compose logs rsyslog
   sudo docker compose logs grafana
   sudo docker compose logs loki
   sudo docker compose logs -f

Before you continue, open the required firewall rules on the collector. For a
host firewall managed with UFW, the minimum rule set is:

.. code-block:: bash

   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw allow 10514/tcp
   sudo ufw allow 6514/tcp

If your environment also uses a provider firewall or security group, mirror the
same access there.

Step 3: Enroll the First Client
-------------------------------

On the client host, download the setup script from the collector and run it
with elevated privileges:

.. code-block:: bash

   wget https://logs.example.com/downloads/install-rsyslog-client.sh
   chmod +x install-rsyslog-client.sh
   sudo ./install-rsyslog-client.sh

Point the client at the collector hostname or IP and choose ``10514`` for
plain TCP or ``6514`` if you already enabled TLS on the collector. The script
tests the generated rsyslog configuration before it restarts the service.

For host metrics, install node_exporter on the client and register the target
from the collector host:

.. code-block:: bash

   wget https://logs.example.com/downloads/install-node-exporter.sh
   chmod +x install-node-exporter.sh
   sudo ./install-node-exporter.sh

   sudo prometheus-target add-client 198.51.100.1 \
        host=web-01 role=web env=production network=internal

The ``add-client`` helper is the best default because it registers both node
metrics and impstats sidecar metrics when present. If you only want basic host
metrics, use ``prometheus-target add CLIENT_IP:9100 ...`` instead.

If the client firewall is enabled, allow the collector to scrape metrics:

.. code-block:: bash

   sudo ufw allow from 198.51.100.10 to any port 9100 proto tcp
   sudo ufw allow from 198.51.100.10 to any port 9898 proto tcp

Replace ``198.51.100.10`` with the collector IP. Port ``9898`` is only needed
when the impstats sidecar is in use.

Step 4: Validate End-to-End Flow
--------------------------------

Send a test event from the client:

.. code-block:: bash

   logger "ROSI walkthrough test from $(hostname)"

Then validate from the collector side and the Grafana UI:

1. Open ``https://logs.example.com`` and sign in to Grafana.
2. Open **Syslog Explorer** and narrow the time range to the last 15 minutes.
3. Filter by the client hostname and confirm the test event appears.
4. Open **Host Metrics Overview** and confirm that the client is visible.

If you did not save the generated admin password, retrieve it from the
collector host:

.. code-block:: bash

   grep GRAFANA_ADMIN_PASSWORD /opt/rosi-collector/.env

.. figure:: /_static/rosi-setup-grafana.png
   :alt: Grafana with ROSI Collector dashboards
   :align: center

   Grafana after the stack and first client are working.

For a quick log query in Grafana Explore, these are good first checks:

.. code-block:: text

   {host="web-01"}
   {host=~".+"} |= "error"
   {facility="auth"}

If logs arrive but metrics do not, the most common cause is that port
``9100/tcp`` is not reachable from the collector. If neither logs nor metrics
arrive, verify DNS, firewall rules, and the client rsyslog restart result.

Production Follow-Up
--------------------

After the first client works, repeat the same enrollment pattern for the rest
of your hosts. For production hardening, the next high-value steps are:

- Enable syslog TLS and choose the appropriate auth mode in :doc:`installation`
- Review dashboard usage and LogQL examples in :doc:`grafana_dashboards`
- Use labels consistently when adding Prometheus targets
- Keep one short validation checklist for every new client onboarding

See Also
--------

- :doc:`installation` for the full install surface and environment variables
- :doc:`client_setup` for manual forwarding and TLS client configuration
- :doc:`grafana_dashboards` for dashboard behavior and query examples
- :doc:`troubleshooting` for failure-oriented diagnostics
