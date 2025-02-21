# Send highstate trigger event for VM deployment status tracking
# so-salt-emit-vm-deployment-status sets event_tag = f'soc/dyanno/hypervisor/{status.lower()}'
vm_highstate_trigger:
  event.send:
    - name: soc/dyanno/hypervisor/highstate triggered
    - data:
        status: Highstate Triggered
        vm_name: {{ grains.id }}
        hypervisor: {{ salt['grains.get']('salt-cloud:profile', '').split('-')[1] }}
    - order: 1  # Ensure this runs early in the highstate process