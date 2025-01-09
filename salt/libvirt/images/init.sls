# the source location will be /opt/so/saltstack/local/salt/libvirt/imaages/coreol9Small
# this will need to change to save the images to /nsm 
baseimagefiles:
  file.recurse:
    - name: /var/lib/libvirt/images/coreol9Small/
    - source: salt://libvirt/images/coreol9Small/
