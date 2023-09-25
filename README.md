# cloud-security-trust-score-calculator
Cloud security trust score calculator
Tool Name: Cloud security trust score calculator

Tool Description:
This tool implements Multi-dimensional Weighted Average Merit Metric Cloud Security Trust Model. As part of this tool we develop a trust score calculator in python for Multi-dimensional Cloud Security Trust Model (MDCSTM).

1. Proposed multi-dimensional cloud security trust calculator calculates trust score on a 10-points scale based on 25 trust metrics (metricSet is a dictionary of 25 metrics. More metrics can be added to enhance the tool further). These trust metrics are security, reliability, and privacy metrics. All metrics are - quantitative, objective, has a time dimension, universally acceptable, inexpensive, obtainable, and repeatable. If there is any new metric is added to dictionary it has to have these attributes so that it can be accepted universally by all cloud vendors and customers.

2. All metrics are divided into two categories - must_be_implemented and should_be_implemented. If any of the must_be_implemented metric is not implemented, final trust score will be calculated ZERO.

3. Each metric has four attributes - merit_value, success_ratio, totaol_weight, and must_be_implemented.
merit_value : assigned by cloud service provider
success_ratio : 0 to 1. For all must_be_implemented metrics it should be one
totaol_weight :  product of merit_value, success_ratio and CONST_METRIC_WEIGHT. CONST_METRIC_WEIGHT is a constant (has value 10).
must_be_implemented : 0 or 1 (decided by cloud service provider)

4. Final trust score calculation
grand_total_of_total_weight = sum of all metrics' total_weight
sum_of_merit_value = sum of all metrics' merit_value
rejection_factor = 0 if any of the must_be_implemented metric is not implemeted, else 1  
final_trust_score = (grand_total_of_total_weight / sum_of_merit_value) * rejection_factor

5. Security decision based on final_trust_score
    if final_trust_score > 9:
        Super! Good for storing restricted, confidential, internal, and declassified information.
    elif final_trust_score > 8:
        Excellent. Good for storing confidential, internal, and declassified information.
    elif final_trust_score > 7:
        Good. Good for storing internal and declassified information
    else:
        Not considerable. Cloud service is good for only declassified information.
        
Author: Krishan Kumar
Email: aapkakk@gmail.com
