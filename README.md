# vpp
---

*vpp source code with the implementation of fairdrop algorithm for bandwidth*

---
### Current work on vpp at Telecom-paristech.

> This branch has the implementation of fairdrop algorithm for bandwidth.

### How to find the fairdrop implementation in the source code.


..* All the functions related to fairdrop can be found in the file `vpp/src/plugins/dpdk/device/flow_table.h`
..* The fairdrop functions are called during the packet processing in the function `dpdk_device_input` which can be found in `vpp/src/plugins/dpdk/device/node.c`
