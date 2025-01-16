# the source location will be /opt/so/saltstack/local/salt/libvirt/images/sool9
# this will need to change to save the images to /nsm 
baseimagefiles:
  file.recurse:
    - name: /var/lib/libvirt/images/sool9/
    - source: salt://libvirt/images/sool9/
