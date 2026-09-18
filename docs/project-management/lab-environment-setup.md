# ZeroShield AI — PostgreSQL and Isolated Laboratory Environment



## Purpose



This document records the development and laboratory environment established for ZeroShield AI under WBS 14 / ZS-014.



The environment separates application infrastructure from the authorised cybersecurity laboratory. PostgreSQL runs locally through Docker, while practical security testing is restricted to an isolated VirtualBox host-only network.



## Docker Environment



Docker Desktop is used with the WSL2 Linux backend.



Verified versions:



- Docker Engine: 29.5.2

- Docker Compose: 5.1.4

- PostgreSQL client: 18.4

- PostgreSQL Docker image: postgres:18.4



The Docker Compose configuration is stored in:



`compose.yml`



Local environment values are stored in:



`.env`



The real `.env` file is excluded from Git. A safe configuration template is provided as:



`.env.example`



## PostgreSQL Configuration



ZeroShield uses a dedicated PostgreSQL Docker container.



Configuration:



- Container name: `zeroshield-postgres`

- Database: `zeroshield`

- Application user: `zeroshield_app`

- PostgreSQL container port: `5432`

- Host binding: `127.0.0.1:5433`

- Persistent volume: `zeroshield-postgres-data`

- Docker network: `zeroshield-backend`



Port 5433 is used on the host because the Windows PostgreSQL 18 service already uses port 5432.



Binding PostgreSQL to `127.0.0.1` prevents unnecessary exposure of the development database to external networks.



## PostgreSQL Health Verification



The PostgreSQL container was verified using:



`docker compose ps`



The container reported:



`healthy`



PostgreSQL readiness was verified using:



`docker compose exec postgres pg_isready -U zeroshield_app -d zeroshield`



The result confirmed:



`/var/run/postgresql:5432 - accepting connections`



A host-side connection was also verified using the PostgreSQL client against:



- Host: `127.0.0.1`

- Port: `5433`

- Database: `zeroshield`

- User: `zeroshield_app`



The connection successfully reported PostgreSQL 18.4.



## VirtualBox Laboratory



VirtualBox version:



`7.2.6r172322`



The isolated laboratory uses the VirtualBox Host-Only Ethernet Adapter.



Network configuration:



- Network: `192.168.171.0/24`

- Windows host interface: `192.168.171.1`

- DHCP: Disabled

- Default gateway on laboratory VMs: None



Laboratory machines:



- Metasploitable2: `192.168.171.3`

- Kali Linux: `192.168.171.4`

- Windows 7: `192.168.171.6`



Each laboratory VM is configured with:



- NIC 1: Disabled

- NIC 2: VirtualBox Host-Only Ethernet Adapter



The previous NAT network attachment was disabled for the laboratory machines.



This prevents the laboratory VMs from having a normal external network route during ZeroShield experiments.



## Laboratory Connectivity Verification



Connectivity was verified inside the isolated network.



Successful communication was confirmed between:



- Kali Linux and Metasploitable2

- Metasploitable2 and Kali Linux

- Windows 7 and Metasploitable2

- Windows 7 and Kali Linux



The laboratory machines have routes for the local `192.168.171.0/24` network and no normal external default gateway.



## Laboratory Safety Boundary



ZeroShield cybersecurity experiments are restricted to the authorised VirtualBox laboratory.



The laboratory must not be used to target:



- public systems,

- university infrastructure,

- production systems,

- third-party systems,

- or systems without explicit authorisation.



NAT or bridged networking should not be enabled during security experiments unless a controlled maintenance activity specifically requires temporary network access.



## Starting the PostgreSQL Environment



Start PostgreSQL:



`docker compose up -d postgres`



Check status:



`docker compose ps`



Check PostgreSQL readiness:



`docker compose exec postgres pg_isready -U zeroshield_app -d zeroshield`



## Stopping the PostgreSQL Environment



Stop the Compose services:



`docker compose down`



The persistent PostgreSQL volume is retained unless it is explicitly removed.



## Evidence



Environment verification evidence is stored under:



`docs/project-management/evidence/lab-environment/`



Current evidence files:



- `docker_postgresql_status.txt`

- `virtualbox_lab_status.txt`



These files record service health, software versions, PostgreSQL readiness, the host-only laboratory network, and VM adapter configuration.