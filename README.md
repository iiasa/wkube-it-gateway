# Gateway for interactivity in WKUBE jobs

- Getway to the internal cluster, from the DMZ (deep NAT).
- Via an internal domain `wkube.iiasa.ac.at`.
- To run interactive ephemeral pod:
  * Jupyter notebooks
  * RStudio server
  * ...
- User set up a `wkube.py` file or a routine in the Accelerator GUI
  with a docker image or Dockerfile defining the interactive container.
- In `wkube.py` config declare on which port inside the container the
  interactive app exposes itself (gets automatically mapped to an outide
  port).
- A WKube agent gets injected into the container with a Kubernetes Init
  Container that runs before the main pod starts.
  * The init container fetches official openssh binary.
  * Used for port forwarding
  * Connects to an SSH port on the gateway (of this repo) on the DMZ
- Agent makes a persistent tunnel from the pod the DMZ and
  exposes it on `<job ID>.wkube.iiasa.ac.at`
  * Temporary URL appears in the WKube log, and user can paste it into
    the browser address bar to connect.
