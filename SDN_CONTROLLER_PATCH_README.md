# SDN controller alignment patch

This patch updates the Ryu controller to make its live seven-feature observations
closer to the CICFlowMeter training representation:

- combines forward and reverse OpenFlow counters for a bidirectional IPv4 5-tuple;
- avoids counting the same conversation multiple times when it appears at several
  switches in the six-switch chain (selects one datapath view, preferring the view
  with the largest packet/byte counters);
- associates FlowStatsReply messages with the request XID and waits for the final
  multipart reply, with a bounded timeout;
- keeps model loading through the existing `ddos_ml.runtime` helper;
- does not enable automatic mitigation.

## Files

- `Codes/controller/controller.py` (replacement)
- `ddos_ml/sdn_runtime.py` (new aggregation helper)
- `tests/test_sdn_runtime.py` (unit tests)

## Install

From the project root:

```bash
unzip -o sdn-controller-alignment-patch.zip -d .
pytest -q tests/test_sdn_runtime.py
python -m py_compile Codes/controller/controller.py ddos_ml/sdn_runtime.py
```

Keep `DDOS_AUTO_MITIGATE=0` (or unset). This patch only improves the data path for
detection; do not enable drops until the model has been validated with Mininet
traffic captured from the same telemetry path.

## Run after Ryu dependencies are installed

Terminal 1:

```bash
cd ~/projects/ddos-cicddos2019-ready/Codes/controller
export DDOS_MODEL_DIR=artifacts/production
ryu-manager --ofp-tcp-listen-port 6653 controller.py
```

`DDOS_MODEL_DIR` is resolved relative to the project root by the controller, so
use the project-relative value `artifacts/production`.

Terminal 2 (Mininet, in the same host/network namespace where Open vSwitch runs):

```bash
cd ~/projects/ddos-cicddos2019-ready/Codes/mininet
sudo python3 topology.py 127.0.0.1
```

Inside the Mininet CLI, start benign traffic first:

```text
mininet> pingall
mininet> h1 ping -c 20 10.0.0.4
mininet> h4 ping -c 20 10.0.0.1
```

Use only the isolated Mininet `10.0.0.0/24` lab for subsequent bounded attack
simulations. Do not point hping3 or flood tools at public or campus networks.

## Important limitations

1. OpenFlow flow counters are cumulative while the rule is installed. They are
   not a perfect replacement for completed CICFlowMeter records.
2. Bidirectional aggregation and selecting one datapath prevent the obvious
   directional and multi-switch double-counting mismatch, but the CIC-trained
   model still requires live Mininet validation before claiming reliable accuracy.
3. The controller logs the representative direction's IP endpoints. Automatic
   mitigation remains separate and disabled by default.
4. Ryu 4.34 is a legacy dependency. Use the separately prepared compatible Ryu
   environment described in `requirements-ryu.txt`; keep the model's pandas,
   NumPy, joblib and scikit-learn versions compatible with the training runtime.
5. This environment did not have Ryu, Mininet or Open vSwitch installed. The
   aggregation helper was unit-tested; the complete OpenFlow integration has not
   been executed here.
