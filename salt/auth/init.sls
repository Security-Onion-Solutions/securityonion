{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.1.4') %}
{% set MASTER = salt['grains.get']('master') %}

so-auth-api-dir:
  file.directory:
    - name: /opt/so/conf/auth/api
    - user: 939
    - group: 939
    - makedirs: True

so-auth-api:
    docker_container.running:
        - image: {{ MASTER }}:5000/soshybridhunter/so-auth-api:{{ VERSION }}
        - hostname: so-auth-api
        - name: so-auth-api
        - environment:
            - BASE_PATH: "/so-auth/api"
            - AUTH_TOKEN_TIMEOUT: 32400
        - binds:
            - /opt/so/conf/auth/api:/data
        - port_bindings:
            - 0.0.0.0:5656:5656

so-auth-ui:
    docker_container.running:
        - image: {{ MASTER }}:5000/soshybridhunter/so-auth-ui:{{ VERSION }}
        - hostname: so-auth-ui
        - name: so-auth-ui
        - port_bindings:
            - 0.0.0.0:4242:80
