*Version 0.1*

## Sample User Story

### Name

Enforce CloudTrail enable if disabled

### Description

CloudTrail logging should be enabled for all AWS accounts and regions. If CloudTrail logging is disabled, it will automatically be enabled and the security operations team will be notified.

### Conditions of Satisfaction

- A Security Hub finding is generated due to CloudTrail logging for a trail being disabled
- A CloudWatch Event filter captures the finding and triggers a Lambda function to enable CloudTrail logging
- A notification is sent to security operations team

### Security Hub Findings

TTPs/Defense Evasion/Stealth:IAMUser-CloudTrailLoggingDisabled
