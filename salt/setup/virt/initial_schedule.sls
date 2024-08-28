init_node_schedule:
  schedule.present:
    - name: init_node
    - function: state.sls
    - job_args:
      - setup.virt.init
    - minutes: 1
