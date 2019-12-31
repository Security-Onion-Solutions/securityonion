so-auth-api-dir:
  file.directory:
    - name: /opt/so/conf/auth/api
    - user: 939
    - group: 939
    - makedirs: True

so-auth-api-image:
    cmd.run:
        - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-auth-api:HH1.1.3

so-auth-ui-image:
    cmd.run:
        - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-auth-ui:HH1.1.3

so-auth-api:
    docker_container.running:
        - require:
            - so-auth-api-image
        - image: docker.io/soshybridhunter/so-auth-api:HH1.1.3
        - hostname: so-auth-api
        - name: so-auth-api
        - environment:
            - BASE_PATH: "/so-auth/api"
        - binds:
            - /opt/so/conf/auth/api:/data
        - port_bindings:
            - 0.0.0.0:5656:5656

so-auth-ui:
    docker_container.running:
        - require:
            - so-auth-ui-image
        - image: docker.io/soshybridhunter/so-auth-ui:HH1.1.3
        - hostname: so-auth-ui
        - name: so-auth-ui
        - port_bindings:
            - 0.0.0.0:4242:80
