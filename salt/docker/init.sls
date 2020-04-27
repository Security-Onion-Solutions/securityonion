installdocker:
  pkg.installed:
    - name: docker-ce

# Make sure Docker is running!
docker:
  service.running:
    - enable: True