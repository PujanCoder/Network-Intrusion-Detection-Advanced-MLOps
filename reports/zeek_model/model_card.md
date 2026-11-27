# Zeek flow classifier - model card

- Version: `2026.11.27-37f7a80`
- Trained at: 2026-11-27T06:40:49+00:00
- Algorithm: hist_gradient_boosting
- Operating threshold: 0.95 (target FPR 5%)
- Training rows: 208,755 (validation 44,733, test 44,734)

## Datasets

| Dataset | Rows used for training/validation/test |
| --- | --- |
| CICIDS2017 | 225,745 |
| UNSW-NB15 | 82,332 |
| NSL-KDD | 125,973 |

## Held-out test performance (binary: malicious vs benign)

| Metric | Value |
| --- | --- |
| Precision | 0.9629 |
| Recall | 0.9831 |
| F1 | 0.9729 |
| False-positive rate | 3.5637% |
| Accuracy | 0.9735 |
| Validation F1 | 0.9723 |
| Test confusion matrix (tn, fp / fn, tp) | [[22217, 821], [366, 21330]] |

## Per-class test performance

| Class | Precision | Recall | F1 | Support |
| --- | --- | --- | --- | --- |
| Analysis | 0.256 | 0.714 | 0.377 | 14 |
| BENIGN | 0.984 | 0.964 | 0.974 | 23,038 |
| Backdoor | 0.125 | 0.250 | 0.167 | 16 |
| BruteForce | 0.754 | 0.980 | 0.852 | 50 |
| DoS | 1.000 | 0.988 | 0.994 | 19,285 |
| Exploit | 0.787 | 0.629 | 0.699 | 1,136 |
| Fuzz | 0.351 | 0.721 | 0.472 | 598 |
| Other | 0.244 | 0.626 | 0.352 | 107 |
| Recon | 0.785 | 0.893 | 0.836 | 484 |
| Worm | 0.375 | 0.500 | 0.429 | 6 |

## Unseen-dataset generalisation

Model retrained without **NSL-KDD (KDDTest+)**, evaluated on its official test partition:

| Metric | Value |
| --- | --- |
| Precision | 0.0000 |
| Recall | 0.0000 |
| F1 | 0.0000 |
| False-positive rate | 0.0000% |

## Error analysis

- False positives in the held-out test: 821
- False negatives in the held-out test: 366
- False-positive profile: {"mean_duration_s": 13.9714, "mean_orig_bytes": 9512.6, "mean_resp_bytes": 13396.1, "mean_pkts_per_s": 52328.14, "mean_dst_port_class": 1.8}
- False-negative profile: {"mean_duration_s": 40.0472, "mean_orig_bytes": 4884.0, "mean_resp_bytes": 7354.8, "mean_pkts_per_s": 7954.27, "mean_dst_port_class": 1.5}
- False negatives by true label: {"Fuzz": 128, "Exploit": 126, "DoS": 72, "Recon": 23, "Other": 13, "Backdoor": 2, "Analysis": 1, "BruteForce": 1}

## Inference latency

- Mean: 2.310 ms/flow (p95 2.922 ms, ~432 flows/s single core)

## Limitations

- The model scores `conn.log` flows only; it is not a full NDR product.
- Cross-dataset feature mapping is approximate by nature (different capture tooling).
- Rule detectors add context for scanning, flooding, brute force, beaconing, exfiltration and DNS tunnelling.
- Scores are decision support, not a replacement for analyst review.
