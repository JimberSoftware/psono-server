# Jimber Server (Psono Server)

## Description

Psono password manager server. This is the backend server that handles password storage, encryption, sharing, and user management. The server runs in a Docker container and integrates with the Jimber OIDC Identity Provider for authentication.

## Quick Start

```bash
cd  psono-server
docker compose -f docker-compose.dev.yaml up -d
```

## Port Information

- **Port**: `10100`
- **URL**: `http://localhost:10100`
- **Note**: Runs in Docker container with code mounted for development

## Dependencies

The server depends on:
- PostgreSQL database (port 5432)
- Jimber OIDC Backend (port 3000)

Both are started automatically via `docker-compose.dev.yaml`.

---

# PSONO Server - Password Manager

[![coverage report](https://gitlab.com/esaqa/psono/psono-server/badges/master/coverage.svg)](https://gitlab.com/esaqa/psono/psono-server/commits/master) [![Code Climate](https://codeclimate.com/github/psono/psono-server/badges/gpa.svg)](https://codeclimate.com/github/psono/psono-server) [![build status](https://img.shields.io/docker/pulls/psono/psono-server.svg)](https://hub.docker.com/r/psono/psono-server/) [![Discord](https://img.shields.io/badge/Discord-join%20chat-738bd7.svg)](https://discord.gg/VmBMzTSbGV)


# Canonical source

The canonical source of PSONO Server is [hosted on GitLab.com](https://gitlab.com/esaqa/psono/psono-server).

# Documentation

The documentation for the psono server can be found here:

[Psono Documentation](https://doc.psono.com/)

Some things that have not yet found their place in the documentation:

## Backup & Restore

For a full backup, you have to backup two things. First thing obviously is the database, and the second thing is your
settings.yaml file as it contains some secrets necessary to decrypt the data in your database.
We have created two little scripts to backup and restore your files in var/backup

#### Backup Process:

For backups follow the following steps.

1. Copy var/backup to a folder of your choosing, example:

        sudo cp -R var/backup /opt/psono-backup
    
2. Update .env file in /opt/psono-backup

3. Execute the backup like:

        /opt/psono-backup/backup
    
4. Schedule backups e.g. for 2:30am daily:

        crontab -e
    
    and add this line:
    
        30 2 * * * /opt/psono-backup/backup

5. Check that backups are created proper a day later.

    If you experience any errors you can check your logs for tips why:
    
        grep CRON /var/log/syslog
        
    Common problems are insufficient user or database rights.


#### Restore Process:

For restoration of a backup follow the following steps.

1. Copy var/backup to a folder of your choosing, example:

        sudo cp -R var/backup /opt/psono-backup
    
2. Update .env file in /opt/psono-backup

3. Execute the backup like:

        /opt/psono-backup/restore --backup=path/to/the/backup/backup_12345.../

## LICENSE

Visit the [License.md](/LICENSE.md) for more details
