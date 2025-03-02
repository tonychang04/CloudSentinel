# CloudSentinel

CloudSentinel is an automated log analysis and threat prevention system for AWS environments. It fetches logs from CloudWatch, analyzes them for potential security threats, and can automatically take preventive actions such as blocking suspicious IP addresses.

## Features

- Automated CloudWatch log fetching and analysis
- Threat detection using pattern matching and keyword analysis
- Automated prevention actions (e.g., blocking IPs in security groups)
- RESTful API for integration with other systems
- Containerized deployment with Docker

## Prerequisites

- AWS account with appropriate permissions
- Docker (for containerized deployment)
- AWS credentials with the following permissions:
  - CloudWatch Logs: `logs:FilterLogEvents`, `logs:GetLogEvents`
  - EC2: Permissions to modify Security Groups

## Setup

### AWS Credentials

Set up your AWS credentials using one of the following methods:

1. Environment variables:
   ```
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_REGION=your_region
   ```

2. AWS credentials file (`~/.aws/credentials`)

3. IAM roles (if deploying on AWS)

### Building and Running with Docker

1. Build the Docker image:
   ```
   docker build -t cloudsentinel .
   ```

2. Run the container:
   ```
   docker run -p 5000:5000 \
     -e AWS_ACCESS_KEY_ID=your_access_key \
     -e AWS_SECRET_ACCESS_KEY=your_secret_key \
     -e AWS_REGION=your_region \
     cloudsentinel
   ```

## API Usage

### Fetch and Analyze Logs 