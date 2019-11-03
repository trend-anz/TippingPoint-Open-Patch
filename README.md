# TippingPoint Open Patch (TPOP)

TPOP enables third parties (Tenable, Rapid7, Qualys, ServiceNow, etc) to easily apply TippingPoint IPS filters. Simply pass TPOP the:

1. Profile name
2. Segment group name
3. CVE of a vulnerability

TPOP will then do the following:

1. Check if the profile has filter(s) applied which protect against the specified CVE. If it doesn't, TPOP adds them
2. Distribute the updated profile to the specified segment 

## Example Output

Provided parameters:

* Profile name: Default
* Segment name: Default
* CVE: CVE-1999-0454

### Run

In this run, `Demo Policy` is created, the relevant IPS rules are applied to it and the host is assigned the newly created policy. 

```
04-Nov-19 06:27:59 - INFO - Obtaining TP API key
04-Nov-19 06:27:59 - INFO - Obtaining SMS address
04-Nov-19 06:27:59 - INFO - Obtained DS address: example.com
04-Nov-19 06:27:59 - INFO - Retrieving profile names
04-Nov-19 06:28:02 - INFO - Converting PROFILE table data to map
04-Nov-19 06:28:02 - INFO - Received CVE-1999-0454 and profile name Default
04-Nov-19 06:28:02 - INFO - Retrieving SIGNATURE table
04-Nov-19 06:28:25 - INFO - Converting SIGNATURE table into a filter number map
04-Nov-19 06:28:26 - INFO - Creating CVE to filter number map
04-Nov-19 06:28:26 - INFO - CVE-1999-0454 maps to filter(s): 79, 81, 82, 163, 164, 290, 291, 292, 293, 302, 303, 304, 307, 308, 309, 310, 311, 317, 321, 324, 325
04-Nov-19 06:28:26 - INFO - Enabling filters...
04-Nov-19 06:28:27 - INFO - Checking the status of filters...
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0079: ICMP: Echo Reply
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0081: ICMP: Unassigned Type (Type 1)
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0082: ICMP: Unassigned Type (Type 2)
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0163: ICMP: Unassigned Type (Type 7)
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0164: ICMP: Echo Request (Ping)
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0290: Invalid TCP Traffic: Possible Recon Scan (SYN FIN)
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0291: Invalid TCP Traffic: Possible Recon Scan (FIN no ACK)
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0292: Invalid TCP Traffic: Possible Recon Scan (No Flags Set)
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0293: Invalid TCP Traffic: Possible Recon Scan (FIN PSH URG Flags Set)
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0302: IPeye Scanner: TCP FIN Probe
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0303: IPeye Scanner: TCP NULL Probe
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0304: IPeye Scanner: TCP XMAS Probe
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0307: Queso: SA OS Fingerprinting Probe
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0308: Queso: FIN OS Fingerprinting Probe
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0309: Queso: FA OS Fingerprinting Probe
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0310: Queso: SF OS Fingerprinting Probe
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0311: Queso: PSH OS Fingerprinting Probe
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0317: Nmap scanner: NULL OS Fingerprinting Probe
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0321: Nmap scanner: FUP OS Fingerprinting Probe
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0324: Invalid TCP Traffic: All Flags Set (Impossible Flags)
04-Nov-19 06:28:29 - INFO - Status: true - Filter: 0325: SynScan: TCP SYN-FIN Probe
04-Nov-19 06:28:29 - INFO - Distributing Default profile to Default segment group
04-Nov-19 06:28:30 - INFO - Successfully added CVE-1999-0454 filter(s) to Default profile and distributed changes to Default segment group
04-Nov-19 06:28:30 - INFO - Returning the output:
{"statusCode": 200, "body": "\"Successfully added CVE-1999-0454 filter(s) to Default profile and distributed changes to Default segment group\""}
04-Nov-19 06:28:30 - INFO - Finished
```

## Response Payloads
### Successful Execution

When a known CVE is provided, the Lambda returns the following JSON payload:

```
{
    "statusCode": 200, 
    "body": "\"Successfully added CVE-1999-0454 filter(s) to Default profile and distributed changes to Default segment group\""
}
```

### Unsuccessful Execution

When an unknown CVE is provided, the Lambda returns the following JSON payload:

```
{
    "statusCode": 400,
    "body": "\"Cannot find an IPS filter for CVE-1999-04534\""
}
```

# User Guide

1. Create an S3 bucket which will be used to store your Lambda.
2. Zip & upload the Lambda:

```
cd code
rm -rf libs/__pycache__/
zip -r9 tippingpoint-open-patch.zip .
cd ..
aws s3 cp tippingpoint-open-patch.zip s3://<LAMBDA_BUCKET_NAME>/tippingpoint-open-patch.zip
rm -rf tippingpoint-open-patch.zip
``` 

3. Validate & run the template:

```
cd ../cfn
aws cloudformation validate-template --template-body file://cfn.yaml
aws cloudformation create-stack \
--stack-name tippingpoint-open-patch-lambda \
--template-body file://cfn.yaml \
--parameters \
ParameterKey=LambdaBucketName,ParameterValue=<BUCKET_NAME> \
ParameterKey=LambdaS3KeyPath,ParameterValue=<S3_KEY_PATH> \
ParameterKey=SmsApiKey,ParameterValue=<API_KEY> \
ParameterKey=SmsApiAddress,ParameterValue=<API_ADDRESS> \
--capabilities CAPABILITY_IAM
```

# Dev Notes
## Update Lambda

If you update the code, you'll need to update Lambda:

```
aws lambda update-function-code \
    --function-name TippingPointOpenPatch \
    --s3-bucket <BUCKET_NAME> \
    --s3-key <S3_KEY_PATH>/tippingpoint-open-patch.zip
```

# Contact

* Blog: oznetnerd.com
* Email: will@oznetnerd.com