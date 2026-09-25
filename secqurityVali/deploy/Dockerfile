# Validator API, containerised for testing.
#
# The validator needs a Docker CLI because validating a submission means
# pulling and running it. It does NOT bundle a daemon: it talks to the host's,
# through the socket mounted by docker-compose.yml.
#
# Read the warning in docker-compose.yml before running this anywhere that
# matters. Mounting the host's Docker socket into a container is equivalent to
# granting root on the host.

FROM docker:27-cli AS dockercli

FROM python:3.13-slim

# Just the client binary -- a few MB, no daemon, no dependencies to manage.
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

WORKDIR /app

# secqurityVali is stdlib-only, so there is nothing to pip install. If that
# ever stops being true, this is where requirements would go.
COPY secqurityVali/ /app/secqurityVali/
COPY neurons/security_vali.py /app/neurons/security_vali.py

# The database lives on a volume so verdicts survive a container rebuild.
ENV SECVAL_DB=/data/secqurityVali.db
VOLUME ["/data"]

EXPOSE 8899

# Runs as root because it needs the mounted Docker socket. That is a
# consequence of the socket mount, not an additional choice -- see the
# compose file.
ENTRYPOINT ["python", "/app/neurons/security_vali.py"]
CMD ["--db", "/data/secqurityVali.db", "serve", "--host", "0.0.0.0", "--port", "8899"]
