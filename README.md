# AWS IAM Policy Visualizer & Analyzer

This project analyzes AWS IAM policies to identify potential security risks, such as overly permissive actions, and provides suggested remediations.  
It can pull IAM policies in real time using `boto3`, highlight high-risk actions, and export the results for review.


## Features
- Pulls IAM policies directly from your AWS account using `boto3`
- Detects risky IAM actions and permissions
- Provides suggested remediations for high-risk findings
- Generates visualizations with `matplotlib`
- Option to export flagged results for documentation or auditing

## Requirements
Install the required dependencies:
```bash
pip install boto3 rich matplotlib
```

You will also need valid AWS credentials with sufficient permissions to read IAM policies.  
These can be configured using:
```bash
aws configure
```


## How to Run
1. Clone this repository:
```bash
git clone https://github.com/YOUR-USERNAME/aws-iam-visualizer.git
cd aws-iam-visualizer
```

2. Run the script:
```bash
python iam_visualizer.py
```

3. Review the console output for flagged policies and recommendations.



## Disclaimer
This tool is intended for educational and auditing purposes.  
Always test in a non-production environment before running in production.
