import random

'''
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
'''
# define constants and variables 
# all metrics will carry a CONSTANT weight
CONST_METRIC_WEIGHT = 10

# simulate trust score on 100 TOTAL_ATTEMPTS
# and randomly generate upto 15 failures
TOTAL_ATTEMPTS = 100
MAX_FAILURE_LIMIT = 15

# initial value of rejection_factor will be 1 if any mandatory 
# metric is not implemented, set rejection_factor = 0
rejection_factor = 1
grand_total_of_total_weight = 0
unimplemented_metric_list = []

metricSet = { 
    'SSL/TLS':
        {
            'merit_value': 25, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 1
        },
        
    'Encryption': 
        {
            'merit_value': 25, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 1
        },

    'Access_Control': 
        {
            'merit_value': 25, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 1
        },
        
    'Input_Sanitization': 
        {
            'merit_value': 25, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 1
        },   

    'Digital_Signatures': 
        {
            'merit_value': 25, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 1
        },

    'Password_Hashing': 
        {
            'merit_value': 25, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 1
        },
		
    'Weak_Passwords': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
		
    'Unsuccessful_Logons': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'Unauthorized_User_Access_Presentation': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'Information_Modification _Presentation': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'Multihead_Approval_For_Information_Modification': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'Consistency metric score': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
		
    'No_Of_Policy_Violations': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'No_Of_Wrong_Roles_Assignment': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'No_Of_Delayed_Software_Updates': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'No_Of_Delayed_Backups': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'Network_Failover': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'High_Availability': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'No. of incidents blocked': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'No_Of_Viruses_Blocked': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'No_Of_Patches_Applied': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
		
    'No_Of_Spam_Blocked': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },

    'No_Of_Virus_Infections': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },

    'No_Of_Port_Probes': 
        {
            'merit_value': 24,
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        },
        
    'Traffic_Analysis_Score': 
        {
            'merit_value': 24, 
            'success_ratio': 0, 
            'totaol_weight': 0,
            'must_be_implemented': 0
        }
}

def simulateSuccessRatio():
    global metricSet
    sr = 0; #initial success_ratio
    
    for metric, values in metricSet.items():
        if metricSet[metric]["must_be_implemented"] == 1:
            sr = 1
            # sr = random.randint(0, 1)
        else:
            if MAX_FAILURE_LIMIT == 0:
                sr = 1
                
            # get a random failure value from 1 to MAX_FAILURE_LIMIT 
            no_of_failures = random.randint(1, MAX_FAILURE_LIMIT)
    
            if no_of_failures == MAX_FAILURE_LIMIT:
                sr = 0
    
            ## calculate percent of successful attempts
            sr = round((TOTAL_ATTEMPTS - no_of_failures) / TOTAL_ATTEMPTS, 2)
            
        metricSet[metric]["success_ratio"] = sr

def trustScoreCalculator(metricSetDict):
    global rejection_factor
    global grand_total_of_total_weight
    global unimplemented_metric_list
    sum_of_merit_value = 0
    
    ## set simulated success ratio for all metrics
    simulateSuccessRatio()
    
    for metric, values in metricSetDict.items():
        metricSetDict[metric]["totaol_weight"] = round(CONST_METRIC_WEIGHT * metricSetDict[metric]["merit_value"] * metricSetDict[metric]["success_ratio"], 2)
        grand_total_of_total_weight += metricSetDict[metric]["totaol_weight"]
        sum_of_merit_value += metricSetDict[metric]["merit_value"]
    
    header = "{:<50} {:>10} {:>15} {:>20} {:>27}".format("Metric_Name", "Weight (W)", "Merit Value (MV)", "Success_Ratio (SR)", "Total Weight (W * MV * SR)")
    separator = "=" * len(header)
    
    print ("SIMULATION PARAMETERS")
    print ("=====================")
    print ("TOTAL ATTEMPTS FOR TRUST SCORE CALCULATION : {0}".format(TOTAL_ATTEMPTS))
    print ("MAX FAILURE THRESHOLD FOR SIMULATION  : {0}".format(MAX_FAILURE_LIMIT))
    print ("CONSTANT WEIGHT FOR EACH METRIC : {0}".format(CONST_METRIC_WEIGHT))
    print ("TRUST CALCULATION SCALE : {0}".format(CONST_METRIC_WEIGHT) + " POINTS\n")

    print(separator)
    print(header)
    print(separator)
    print("\nMANDATORY METRICS (MUST BE IMPLEMENTED)")
    print("---------------------------------------")
    
    for metric, values in metricSetDict.items():
        line = "{:<50} {:>10} {:>15} {:>20} {:>27}".format(metric, CONST_METRIC_WEIGHT, \
        metricSetDict[metric]["merit_value"], \
        metricSetDict[metric]["success_ratio"], \
        metricSetDict[metric]["totaol_weight"]) 
        
        if metricSetDict[metric]["must_be_implemented"] == 1:
            print(line)
            if metricSetDict[metric]["success_ratio"] == 0:
                rejection_factor = 0
                unimplemented_metric_list.append(metric)
                
            
    print("\nOTHER METRICS (SHOULD BE IMPLEMENTED)")
    print("-------------------------------------")
    
    for metric, values in metricSetDict.items():
        line = "{:<50} {:>10} {:>15} {:>20} {:>27}".format(metric, CONST_METRIC_WEIGHT, \
        metricSetDict[metric]["merit_value"], \
        metricSetDict[metric]["success_ratio"], \
        metricSetDict[metric]["totaol_weight"])
        
        if metricSetDict[metric]["must_be_implemented"] == 0:
            print(line)        

    print(separator)
    print("Calculated weight of all metrics : {0:>42} {1:>48}".format(str(sum_of_merit_value), str(round(grand_total_of_total_weight, 2))))
    print(separator)
    
    ### trust score calculation
    no_of_metrics = len(metricSetDict)
    final_trust_score = (grand_total_of_total_weight / sum_of_merit_value) * rejection_factor

    print("\n\n\nTRUST SCORE REPORT")
    
    print(separator)
    print("Total number of metrics used for trust score calculation : {:>67}".format(str(round(no_of_metrics, 2))))
    print("Final trust score on {0} points scale : {1:>87}".format(CONST_METRIC_WEIGHT, str(round(final_trust_score, 2))))
    
    if len(unimplemented_metric_list) != 0:
        print("\n\nTRUST SCORE IS ZERO BECAUSE OF FOLLOWING METRICS NOT IMPLEMENTED:\n")
        print(*unimplemented_metric_list, sep='\n')
    print(separator)
    
    ## print the eligibility of usage
    if final_trust_score > 9:
        print("Cloud security score is super! Good for storing restricted, confidential, internal and declassified information.")
    elif final_trust_score > 8:
        print("Cloud security score is excellent! Good for storing confidential, internal and declassified information.")
    elif final_trust_score > 7:
        print("Cloud security score is good. Good for storing internal and declassified information.")
    else:
        print("Cloud security score is not considerable. Cloud service is good for only declassified information.")

if __name__ == "__main__":
    trustScoreCalculator(metricSet)


