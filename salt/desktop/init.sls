include:
  - desktop.xwindows
{# If the master is 'salt' then the minion hasn't been configured and isn't connected to the grid. #}
{# We need this since the trusted-ca state uses mine data. #}
{% if grains.master != 'salt' %}
  - desktop.trusted-ca
{% endif %}
